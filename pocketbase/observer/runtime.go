package observer

import (
	"context"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"log"
	"myapp/debugtrace"
	"sync"
	"time"
)

type Config struct {
	DNSLogPath, ConntrackPath, AccountingPath string
	SampleInterval                            time.Duration
	Scope                                     ObservationScope
	Packet                                    PacketActivityConfig
}

func ConfigFromEnv(ap string) Config {
	return Config{
		DNSLogPath:     envString("DNSMASQ_LOG_PATH", "/var/log/dnsmasq.log"),
		ConntrackPath:  envString("CONNTRACK_PATH", "/proc/net/nf_conntrack"),
		AccountingPath: envString("CONNTRACK_ACCOUNTING_PATH", "/proc/sys/net/netfilter/nf_conntrack_acct"),
		SampleInterval: time.Duration(boundedEnvInt("CONNTRACK_SAMPLE_MS", 1000, 250, 5000)) * time.Millisecond,
		Scope:          NewObservationScope(envString("CLIENT_CIDRS", envString("CLIENT_IP_PREFIX", "10.0.0.0/24")), envString("GATEWAY_IP", "10.0.0.1")),
		Packet:         PacketActivityConfigFromEnv(ap),
	}
}

// Runtime hides the source, derivation, lookup and persistence worker wiring.
// Quiesce joins all workers; Start creates fresh DNS/packet state while retaining
// conntrack suppression. Clear can therefore use a full stop as its generation
// fence instead of maintaining several independent reset protocols.
type Runtime struct {
	app       *pocketbase.PocketBase
	geo       *geoip2.Reader
	config    Config
	sessionID func() string
	trace     debugtrace.Sink
	sampler   *ConntrackSampler
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	stopErr   error
	closed    bool
}

func New(app *pocketbase.PocketBase, geo *geoip2.Reader, config Config, sessionID func() string, trace debugtrace.Sink, onFlow func(CommittedFlow)) *Runtime {
	if config.SampleInterval <= 0 {
		config.SampleInterval = time.Second
	}
	sampler := NewConntrackSampler(config.ConntrackPath, config.Scope)
	sampler.trace = usableTraceSink(trace)
	sampler.routeObserver = onFlow
	return &Runtime{app: app, geo: geo, config: config, sessionID: sessionID, trace: usableTraceSink(trace), sampler: sampler}
}

func (r *Runtime) Start() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed || r.cancel != nil {
		return
	}
	if r.done != nil {
		select {
		case <-r.done:
		default:
			return
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	r.stopErr = nil
	if _, err := ensureConntrackAccounting(r.config.AccountingPath); err != nil {
		log.Printf("conntrack accounting unavailable: %v", err)
	}
	dns := &DNSMasqIngestor{app: r.app, path: r.config.DNSLogPath, scope: r.config.Scope, sessionID: r.sessionID, recentByName: map[string][]recentDNSQuery{}, recentBySerial: map[string][]recentDNSQuery{}, trace: r.trace}
	packet := startPacketPipeline(r.app, r.config.Scope, r.sessionID, r.config.Packet, r.trace, runPacketCapture)
	destinations := make(chan []DestinationObservation, 1)
	var workers sync.WaitGroup
	launch := func(f func()) { workers.Add(1); go func() { defer workers.Done(); f() }() }
	launch(func() { dns.run(ctx) })
	launch(func() { r.sampler.run(ctx, r.app, r.sessionID, r.config.SampleInterval) })
	launch(func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()
		for {
			if ctx.Err() != nil {
				return
			}
			if id := r.sessionID(); id != "" {
				rows, err := deriveSession(r.app, r.config.Scope, id, r.trace)
				if err != nil {
					log.Printf("observation derivation: %v", err)
				} else {
					// At most one waiting snapshot; replace stale lookup work with newest inputs.
					select {
					case <-destinations:
					default:
					}
					select {
					case destinations <- rows:
					case <-ctx.Done():
						return
					}
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	launch(func() {
		for {
			select {
			case <-ctx.Done():
				return
			case rows := <-destinations:
				for _, observation := range rows {
					if ctx.Err() != nil {
						return
					}
					record, changed, err := upsertDestination(ctx, r.app, r.geo, observation)
					if err != nil {
						log.Printf("destination enrichment: %v", err)
						break
					}
					if changed {
						emitDestinationTrace(r.trace, observation, record)
					}
				}
			}
		}
	})
	done := r.done
	go func() {
		<-ctx.Done()
		// Cancel capture promptly; chunk drain may proceed alongside the other joins.
		packet.stopCapture()
		workers.Wait()
		err := packet.Close(context.Background())
		r.mu.Lock()
		r.stopErr = err
		r.mu.Unlock()
		close(done)
	}()
}

func (r *Runtime) Quiesce(ctx context.Context) error {
	r.mu.Lock()
	if r.cancel != nil {
		r.cancel()
		r.cancel = nil
	}
	r.mu.Unlock()
	return r.Wait(ctx)
}

// Wait joins the current generation without changing its state.
func (r *Runtime) Wait(ctx context.Context) error {
	r.mu.Lock()
	done := r.done
	r.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return fmt.Errorf("observation join: %w", ctx.Err())
		}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.stopErr
}

func (r *Runtime) Close(ctx context.Context) error {
	r.mu.Lock()
	r.closed = true
	r.mu.Unlock()
	return r.Quiesce(ctx)
}
func (r *Runtime) SuppressCurrentFlows() error { return r.sampler.SuppressCurrentFlows() }
