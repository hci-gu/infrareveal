package observer

import (
	"bufio"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"log"
	"myapp/data"
	"myapp/debugtrace"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Runtime has one owner of capture/classification state, a bounded input queue,
// and independent optional diagnostics. Cancellation drains accepted packets
// before the final commit; a caller timeout never closes a worker's resources.
type Runtime struct {
	app       *pocketbase.PocketBase
	geo       *geoip2.Reader
	config    Config
	sessionID func() string
	trace     debugtrace.Sink
	onTraffic func(CommittedTraffic)
	mu        sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	stopErr   error
	closed    bool
	lossAt    atomic.Int64
}

func New(app *pocketbase.PocketBase, geo *geoip2.Reader, config Config, sessionID func() string, trace debugtrace.Sink, onTraffic func(CommittedTraffic)) *Runtime {
	if config.SampleInterval <= 0 {
		config.SampleInterval = time.Second
	}
	if config.Packet.FlushInterval <= 0 {
		config.Packet.FlushInterval = 400 * time.Millisecond
	}
	if config.Packet.EventQueueSize <= 0 {
		config.Packet.EventQueueSize = 8192
	}
	if config.Packet.MaxPendingChunks <= 0 {
		config.Packet.MaxPendingChunks = 4096
	}
	if config.NetworkEpoch == nil {
		config.NetworkEpoch = func() string { return "" }
	}
	return &Runtime{app: app, geo: geo, config: config, sessionID: sessionID, trace: usableTraceSink(trace), onTraffic: onTraffic}
}

type sourceEvent struct {
	session string
	at      time.Time
	packet  *PacketActivityEvent
	dns     *dnsLogEvent
	samples []FlowSample
	leases  map[string]string
	status  string
	reason  string
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
		log.Printf("optional conntrack accounting: %v", err)
	}
	events := make(chan sourceEvent, r.config.Packet.EventQueueSize)
	var lost atomic.Int64
	r.lossAt.Store(0)
	var sources sync.WaitGroup
	launch := func(f func()) { sources.Add(1); go func() { defer sources.Done(); f() }() }
	send := func(e sourceEvent, packet bool) {
		e.session = r.sessionID()
		if e.at.IsZero() {
			e.at = time.Now()
		}
		select {
		case events <- e:
		default:
			if packet {
				lost.Add(1)
				r.lossAt.Store(e.at.UnixMilli())
			}
		}
	}
	launch(func() {
		if !r.config.Packet.Enabled {
			send(sourceEvent{status: "unavailable", reason: "capture disabled"}, false)
			return
		}
		for ctx.Err() == nil {
			err := runPacketCaptureHealth(ctx, r.config.Packet.Interface, r.config.Scope, func() {
				// A readiness event is ordered ahead of captured packets.
				select {
				case events <- sourceEvent{session: r.sessionID(), at: time.Now(), status: "complete"}:
				case <-ctx.Done():
				}
			}, func(p PacketActivityEvent) { send(sourceEvent{packet: &p, at: p.ObservedAt}, true) }, func(at time.Time, dropped int64) {
				lost.Add(dropped)
				if dropped > 0 {
					r.lossAt.Store(at.UnixMilli())
				}
				send(sourceEvent{at: at, status: "heartbeat"}, false)
			})
			if ctx.Err() != nil {
				return
			}
			reason := "capture stopped"
			if err != nil {
				reason = err.Error()
			}
			select {
			case events <- sourceEvent{session: r.sessionID(), at: time.Now(), status: "unavailable", reason: reason}:
			case <-ctx.Done():
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
		}
	})
	if r.config.DNSLogPath != "" {
		launch(func() {
			d := DNSMasqIngestor{path: r.config.DNSLogPath, emit: func(e dnsLogEvent) { send(sourceEvent{dns: &e}, false) }}
			d.run(ctx)
		})
	}
	launch(func() {
		ticker := time.NewTicker(r.config.SampleInterval)
		defer ticker.Stop()
		for {
			samples, err := ReadConntrackSamples(r.config.ConntrackPath, r.config.Scope)
			leases := readLeases(r.config.LeasePath)
			if err == nil || len(leases) > 0 {
				send(sourceEvent{samples: samples, leases: leases}, false)
			}
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	})
	go func() { sources.Wait(); close(events) }()
	done := r.done
	go func() { err := r.consume(events, &lost); r.mu.Lock(); r.stopErr = err; r.mu.Unlock(); close(done) }()
}

func readLeases(path string) map[string]string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	leases := map[string]string{}
	scanner := bufio.NewScanner(f)
	for scanner.Scan() && len(leases) < 1024 {
		parts := strings.Fields(scanner.Text())
		if len(parts) >= 3 && normalizedIP(parts[2]) != "" {
			leases[normalizedIP(parts[2])] = strings.ToLower(parts[1])
		}
	}
	return leases
}

func (r *Runtime) consume(events <-chan sourceEvent, lost *atomic.Int64) error {
	ticker := time.NewTicker(r.config.Packet.FlushInterval)
	defer ticker.Stop()
	// Block rebuilding and optional writes are independently bounded workers.
	project := make(chan string, 1)
	projectDone := make(chan struct{})
	go func() {
		defer close(projectDone)
		for session := range project {
			if err := RebuildBlocks(r.app, session, time.Now().UnixMilli()); err != nil && !errors.Is(err, sql.ErrNoRows) {
				log.Printf("activity blocks: %v", err)
			}
		}
	}()
	diagnostics := make(chan diagnosticWrite, 256)
	diagnosticsDone := make(chan struct{})
	go func() {
		defer close(diagnosticsDone)
		for w := range diagnostics {
			if time.Since(w.queued) > 5*time.Second {
				continue
			}
			err := r.app.RunInTransaction(func(tx core.App) error {
				if _, err := tx.FindRecordById("sessions", w.session); err != nil {
					return err
				}
				_, err := data.Write(tx, w.collection, w.value)
				return err
			})
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				log.Printf("optional diagnostics: %v", err)
			}
		}
	}()
	defer func() { close(diagnostics); <-diagnosticsDone; close(project); <-projectDone }()
	diagnostic := func(session, collection string, value any) {
		if r.config.Diagnostics {
			select {
			case diagnostics <- diagnosticWrite{collection: collection, session: session, value: value, queued: time.Now()}:
			default:
			}
		}
	}
	var a *aggregate
	destinations := map[string]data.Destination{}
	byIP := map[string]string{}
	var current, lastCoverage data.CaptureInterval
	var pending []data.CaptureInterval
	var confirmed, savedEnd, drops, lastProject, lossUntil int64
	running := false
	reason := "capture starting"
	interval := func(at int64, quality, why string) data.CaptureInterval {
		return data.CaptureInterval{ID: data.NewID(), Session: a.session, CaptureEpoch: a.epoch, StartMS: at, EndMS: at, Quality: quality, Reason: why}
	}
	flush := func(now int64, final bool) error {
		if a == nil {
			return nil
		}
		lossUntil = max(lossUntil, r.lossAt.Load(), a.lossAt)
		drops += lost.Swap(0) + a.dropped
		a.dropped = 0
		if !running {
			current.EndMS = max(current.EndMS, now)
			confirmed = max(confirmed, now)
		}
		if drops > 0 && running && current.Quality != "partial" {
			end := current.EndMS
			if lastCoverage.Quality == "partial" && lastCoverage.EndMS == current.StartMS {
				current = lastCoverage
			} else {
				current.EndMS = max(current.StartMS, savedEnd)
				pending = append(pending, current)
				current = interval(current.EndMS, "partial", "capture or persistence queue overflow")
			}
			current.EndMS = end
		}
		current.Dropped += drops
		coverage := append(append([]data.CaptureInterval{}, pending...), current)
		logicalNow := now
		if running {
			logicalNow = min(now, confirmed)
		}
		chunks := a.snapshot(logicalNow)
		if final {
			for i := range chunks {
				chunks[i].Sealed = true
			}
		}
		health := data.CaptureHealth{Running: running && !final, ConfirmedMS: confirmed, Quality: current.Quality, Error: reason, Dropped: drops}
		floor, err := persistCapture(r.app, a.session, a.epoch, a.generation, chunks, destinations, coverage, health)
		if err != nil {
			current.Dropped -= drops
			return err
		}
		for _, delta := range a.pending {
			if r.onTraffic != nil {
				r.onTraffic(delta)
			}
		}
		for _, f := range a.flows {
			diagnostic(a.session, "flow_diagnostics", diagnosticFlow(a, f))
		}
		a.committed(logicalNow, floor)
		pending = nil
		drops = 0
		savedEnd = current.EndMS
		lastCoverage = current
		if current.Quality == "partial" && running && confirmed >= lossUntil {
			current = interval(savedEnd, "complete", "")
		}
		// Keep only snapshots needed by the bounded tail; stable IDs let future
		// packets reuse the same stored version without retaining an unbounded cache.
		if len(byIP) > 2048 {
			byIP = map[string]string{}
			keep := map[string]data.Destination{}
			for _, p := range a.parts {
				keep[p.chunk.DestinationID] = destinations[p.chunk.DestinationID]
			}
			destinations = keep
		}
		if final {
			return RebuildBlocks(r.app, a.session, now)
		}
		if now-lastProject >= 3000 {
			select {
			case project <- a.session:
				lastProject = now
			default:
			}
		}
		return nil
	}
	switchSession := func(id string, now int64) error {
		if a != nil && a.session == id {
			return nil
		}
		if err := flush(now, true); err != nil && !errors.Is(err, sql.ErrNoRows) && !errors.Is(err, errStaleFlush) {
			return err
		}
		a = nil
		lastCoverage = data.CaptureInterval{}
		pending = nil
		destinations = map[string]data.Destination{}
		byIP = map[string]string{}
		drops = 0
		savedEnd = 0
		confirmed = 0
		if id == "" {
			return nil
		}
		epoch := data.NewID()
		session, err := beginCapture(r.app, id, epoch)
		if err != nil {
			return err
		}
		policy := session.Policy
		if policy.BucketMS == 0 {
			policy = DefaultPolicy()
		}
		a = newAggregate(id, epoch, policy, r.config.Packet.MaxPendingChunks)
		a.frozenBefore = max(session.StartedMS, session.RetainedFromMS, session.Capture.ConfirmedMS/policy.BucketMS*policy.BucketMS)
		quality := "unavailable"
		if running {
			quality = "complete"
		}
		current = interval(now, quality, reason)
		confirmed = now
		return nil
	}
	for {
		select {
		case e, ok := <-events:
			now := time.Now().UnixMilli()
			if !ok {
				for {
					err := flush(time.Now().UnixMilli(), true)
					if err == nil || errors.Is(err, sql.ErrNoRows) || errors.Is(err, errStaleFlush) {
						return nil
					}
					log.Printf("capture drain retry: %v", err)
					time.Sleep(500 * time.Millisecond)
				}
			}
			if err := switchSession(r.sessionID(), now); err != nil {
				log.Printf("capture session: %v", err)
				continue
			}
			if a == nil || e.session != a.session {
				continue
			}
			at := e.at.UnixMilli()
			if e.status != "" {
				if e.status == "heartbeat" {
					if running {
						current.EndMS = max(current.EndMS, at)
						confirmed = max(confirmed, at)
					}
					continue
				}
				if running {
					current.EndMS = max(current.EndMS, confirmed)
				} else {
					current.EndMS = max(current.EndMS, at)
				}
				if len(pending) < 256 {
					pending = append(pending, current)
				}
				running = e.status == "complete"
				reason = e.reason
				start := at
				if !running {
					start = confirmed
				}
				current = interval(start, e.status, reason)
				current.EndMS = at
				confirmed = max(confirmed, at)
			}
			if e.packet != nil {
				p := *e.packet
				ip := p.Tuple.RemoteIP.String()
				if !p.Tuple.RemoteIP.IsValid() {
					if t, ok := tupleFromKey(p.FlowKey); ok {
						p.Tuple = t
						ip = t.RemoteIP.String()
					} else {
						continue
					}
				}
				id := byIP[ip]
				if id == "" {
					if len(byIP) >= 2048 {
						byIP = map[string]string{}
						keep := map[string]data.Destination{}
						for _, p := range a.parts {
							keep[p.chunk.DestinationID] = destinations[p.chunk.DestinationID]
						}
						destinations = keep
					}
					d := destinationSnapshot(r.geo, ip, e.at)
					id = d.ID
					destinations[id] = d
					byIP[ip] = id
				}
				a.packet(p, r.config.NetworkEpoch(), destinations[id])
				r.trace.TryBurst(debugtrace.BurstInput{SessionID: a.session, TraceID: "capture:" + p.FlowKey, FlowKey: p.FlowKey, Protocol: p.Tuple.Protocol, Direction: debugtrace.Direction(p.Direction), OccurredAtMs: p.ObservedAt.UnixMilli(), WireBytes: uint64(p.WireBytes), PayloadBytes: uint64(p.PayloadBytes), PacketCount: 1, TCPFlags: p.TCPFlags})
			}
			if e.dns != nil {
				for _, q := range a.dns.add(a.session, *e.dns, at, r.config.Scope) {
					diagnostic(a.session, "dns_queries", q)
					r.trace.TryEmit(debugtrace.Event{ID: fmt.Sprintf("dns:%s:%d", q.ID, len(q.Answers)), SessionID: a.session, TraceID: "dns:" + q.ID, Kind: debugtrace.KindDNS, Stage: debugtrace.StageDNS, OccurredAtMs: q.ObservedMS, Timing: debugtrace.TimingObserved, Summary: debugtrace.Summary{ClientIP: q.ClientIP, DNSName: q.QueryName, DNSType: q.QueryType}})
				}
			}
			for ip, mac := range e.leases {
				a.client(ip, mac)
			}
			if e.samples != nil {
				a.conntrack(e.samples, at)
			}
		case now := <-ticker.C:
			if err := switchSession(r.sessionID(), now.UnixMilli()); err != nil {
				log.Printf("capture session: %v", err)
				continue
			}
			if err := flush(now.UnixMilli(), false); err != nil && !errors.Is(err, sql.ErrNoRows) {
				log.Printf("capture flush: %v", err)
			}
		}
	}
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
