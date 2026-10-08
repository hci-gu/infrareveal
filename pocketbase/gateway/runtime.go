package gateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"log"
	"myapp/debugtrace"
	"myapp/labgate"
	"myapp/observer"
	"myapp/routing"
	"sync"
	"sync/atomic"
	"time"
)

// Runtime owns one gateway's resources and installed (committed) session identity.
// Start and Close are serialized with clear and maintenance. New does no I/O.
type Runtime struct {
	app               *pocketbase.PocketBase
	config            Config
	activeSessionID   atomic.Pointer[string]
	operations        sync.Mutex
	closeMu           sync.Mutex
	resourcesClosed   bool
	registered        sync.Once
	started, closed   bool
	traceHub          *debugtrace.Hub
	trace             debugtrace.Sink
	gate              *labgate.Controller
	audit             *labgate.AuditWriter
	controlToken      []byte
	geo               *geoip2.Reader
	routes            *routing.Coordinator
	observation       *observer.Runtime
	cancelMaintenance context.CancelFunc
	maintenanceDone   chan struct{}
	maintenance       struct {
		sync.RWMutex
		status demoMaintenanceStatus
	}
}

func New(app *pocketbase.PocketBase, config Config) *Runtime {
	return &Runtime{app: app, config: config}
}

func (g *Runtime) Register() {
	g.registered.Do(func() {
		g.registerSessionHooks()
		g.app.OnServe().BindFunc(func(e *core.ServeEvent) error {
			if err := g.Start(); err != nil {
				return err
			}
			g.registerRoutes(e.Router)
			if err := e.Next(); err != nil {
				ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
				defer cancel()
				return errors.Join(err, g.Close(ctx))
			}
			return nil
		})
		g.app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error {
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := g.Close(ctx); err != nil {
				log.Printf("gateway shutdown: %v", err)
				if g.resourcesClosed {
					return errors.Join(err, e.Next())
				}
				return err
			}
			return e.Next()
		})
	})
}

func (g *Runtime) Start() (err error) {
	g.operations.Lock()
	defer g.operations.Unlock()
	if g.closed {
		return fmt.Errorf("gateway is closed")
	}
	if g.started {
		return nil
	}
	defer func() {
		if err != nil {
			g.closed = true // failed startup is terminal; Close can retry any unfinished joins
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			err = errors.Join(err, g.closeResources(ctx))
		}
	}()
	g.resourcesClosed = false
	g.config.Trace.LogEffective()
	g.config.Gate.LogEffective()
	g.traceHub, g.trace = debugtrace.NewRuntime(context.Background(), g.config.Trace)
	auditSink := labgate.AuditSink(labgate.NopAuditSink{})
	if g.config.Gate.Enabled {
		g.audit = labgate.NewAuditWriter(g.app, 512)
		auditSink = g.audit
	}
	if path := g.config.Gate.ControlTokenFile; path != "" {
		var tokenErr error
		g.controlToken, tokenErr = labgate.LoadControlToken(path)
		if tokenErr != nil {
			log.Printf("lab gate controls unavailable: %v", tokenErr)
		}
	}
	g.gate, err = newLabGateRuntime(context.Background(), g.config.Gate, g.trace, g.config.APInterface, g.config.InternetInterface, g.config.ClientSubnetText, auditSink)
	if err != nil {
		return err
	}
	g.geo, _ = geoip2.Open(g.config.GeoIPPath)
	if err = g.ensureDefaultActiveSession(); err != nil {
		return fmt.Errorf("ensure active gateway session: %w", err)
	}
	g.routes = routing.Start(context.Background(), g.app, g.geo, g.CurrentSessionID, g.config.Routes)
	g.observation = observer.New(g.app, g.geo, g.config.Observation, g.CurrentSessionID, g.trace, func(f observer.CommittedFlow) {
		g.routes.Observe(routing.Flow{Baseline: f.Baseline, ID: f.ID, Session: f.Session, IP: f.IP, Protocol: f.Protocol, Port: f.Port, Bytes: f.Bytes, At: f.At})
	})
	g.observation.Start()
	ctx, cancel := context.WithCancel(context.Background())
	g.cancelMaintenance = cancel
	g.maintenanceDone = make(chan struct{})
	go func() { defer close(g.maintenanceDone); g.maintain(ctx) }()
	g.started = true
	return nil
}

func (g *Runtime) Close(ctx context.Context) error {
	if err := lockOperation(ctx, &g.closeMu); err != nil {
		return err
	}
	defer g.closeMu.Unlock()
	// Stop maintenance before taking its operation lock, then join every resource.
	// cancelMaintenance is installed before Start releases operations.
	if err := lockOperation(ctx, &g.operations); err != nil {
		return err
	}
	if g.resourcesClosed {
		g.operations.Unlock()
		return nil
	}
	g.closed = true
	if g.cancelMaintenance != nil {
		g.cancelMaintenance()
	}
	done := g.maintenanceDone
	g.operations.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if err := lockOperation(ctx, &g.operations); err != nil {
		return err
	}
	defer g.operations.Unlock()
	return g.closeResources(ctx)
}

func (g *Runtime) closeResources(ctx context.Context) error {
	var errs []error
	var gateErr error
	if g.gate != nil {
		gateErr = g.gate.Close(ctx)
		errs = append(errs, gateErr)
	}
	if g.observation != nil {
		errs = append(errs, g.observation.Close(ctx))
	}
	if g.routes != nil {
		errs = append(errs, g.routes.Close(ctx))
	}
	if g.audit != nil && ctx.Err() == nil {
		errs = append(errs, g.audit.Close(ctx))
	}
	// A timed-out worker still owns these dependencies. Leave them available for
	// a subsequent Close, never close storage/lookup handles beneath a writer.
	if ctx.Err() != nil {
		return errors.Join(append(errs, ctx.Err())...)
	}
	if g.traceHub != nil {
		g.traceHub.Close()
	}
	if g.geo != nil {
		_ = g.geo.Close()
		g.geo = nil
	}
	g.started = false
	g.resourcesClosed = true
	return errors.Join(errs...)
}

func (g *Runtime) CurrentSessionID() string {
	if id := g.activeSessionID.Load(); id != nil {
		return *id
	}
	return ""
}

// Context-aware operation entry keeps shutdown and clear bounded even while a
// database operation is still finishing. The owner continues and can be joined.
func lockOperation(ctx context.Context, mu *sync.Mutex) error {
	for !mu.TryLock() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Millisecond):
		}
	}
	return nil
}
