// Package routing collects finite gateway route approximations without touching
// client forwarding. Demand is captured traffic, not stored connections.
package routing

import (
	"context"
	"fmt"
	"math"
	"myapp/data"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase/core"
)

type demand struct {
	binding         routeBinding
	first, last     time.Time
	buckets         map[int64]int64
	manual, running bool
	state           string
	generation      uint64
	cancel          context.CancelFunc
	pending         []probeResult
	retry           time.Time
}

func (d *demand) weight(now time.Time) int64 {
	var total int64
	for sec, n := range d.buckets {
		if sec < now.Add(-30*time.Second).Unix() {
			delete(d.buckets, sec)
		} else {
			total = safeAdd(total, n)
		}
	}
	return total
}
func (d *demand) qualified(now time.Time, minimum int64) bool {
	if d.weight(now) >= minimum {
		return true
	}
	first, last, count := int64(math.MaxInt64), int64(0), 0
	for sec, n := range d.buckets {
		if n > 0 {
			first = min(first, sec)
			last = max(last, sec)
			count++
		}
	}
	return count >= 3 && last-first >= 10
}
func safeAdd(a, b int64) int64 {
	if b > math.MaxInt64-a {
		return math.MaxInt64
	}
	return a + b
}

type probeResult struct {
	key        string
	generation uint64
	attempt    admission
	value      snapshot
	enriched   bool
}
type manualRequest struct {
	ChunkID string
	Reply   chan error
}
type Coordinator struct {
	mu         sync.Mutex
	intake     map[string]Traffic
	deferred   int
	stats      Stats
	epoch      string
	reset      chan chan struct{}
	done, stop chan struct{}
	closeOnce  sync.Once
	requests   chan manualRequest
	repo       evidenceStore
	config     Config
	probe      prober
	enrich     func(context.Context, snapshot) snapshot
	session    func() string
	network    func() (string, error)
}

func Start(ctx context.Context, app core.App, geo *geoip2.Reader, session func() string, config Config) *Coordinator {
	if config.MaxSnapshots == 0 {
		config = defaultConfig()
	}
	engine := scamperProbe{deadline: config.ProbeDeadline}
	c := &Coordinator{intake: map[string]Traffic{}, reset: make(chan chan struct{}), done: make(chan struct{}), stop: make(chan struct{}), requests: make(chan manualRequest, 10), repo: newEvidenceStore(app, geo, config), config: config, probe: engine, session: session, network: networkContext}
	go c.run(ctx)
	return c
}
func (c *Coordinator) Close(ctx context.Context) error {
	c.closeOnce.Do(func() { close(c.stop) })
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Coordinator) NetworkEpoch() string { c.mu.Lock(); defer c.mu.Unlock(); return c.epoch }
func (c *Coordinator) Observe(f Traffic) {
	select {
	case <-c.stop:
		return
	default:
	}
	ip, err := netip.ParseAddr(f.IP)
	if err != nil || f.Session == "" || f.NetworkEpoch == "" || f.Bytes <= 0 || f.At.IsZero() || (f.Protocol != "tcp" && f.Protocol != "udp") || f.Port < 1 || f.Port > 65535 {
		return
	}
	f.IP = ip.Unmap().String()
	c.mu.Lock()
	defer c.mu.Unlock()
	key := fmt.Sprintf("%s|%s|%s|%s|%d|%d", f.Session, f.NetworkEpoch, f.IP, f.Protocol, f.Port, f.At.Unix())
	old, ok := c.intake[key]
	if !ok && len(c.intake) >= c.config.MaxPending*16 {
		c.deferred++
		return
	}
	f.Bytes = safeAdd(old.Bytes, f.Bytes)
	c.intake[key] = f
}
func (c *Coordinator) Status() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Targets = append([]TargetStatus{}, s.Targets...)
	return s
}
func (c *Coordinator) ResetContext(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case c.reset <- ack:
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-ack:
		return nil
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Coordinator) Measure(ctx context.Context, chunkID string) error {
	req := manualRequest{ChunkID: chunkID, Reply: make(chan error, 1)}
	select {
	case c.requests <- req:
	case <-c.stop:
		return fmt.Errorf("route discovery stopped")
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-req.Reply:
		return err
	case <-c.stop:
		return fmt.Errorf("route discovery stopped")
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Coordinator) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer close(c.done)
	c.repo.config = c.config
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	updates := make(chan probeResult, 4)
	networks := make(chan string, 1)
	slots := make(chan struct{}, 1)
	enricher := newInterfaceEnricher(c.config.ASNDBPath)
	defer enricher.close()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait(); _ = c.repo.recoverAdmissions(time.Now().UTC()) }()
	lastError := ""
	if err := c.repo.recoverAdmissions(time.Now().UTC()); err != nil {
		lastError = err.Error()
	}
	workers.Add(1)
	go func() {
		defer workers.Done()
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		for {
			n, err := c.network()
			if err != nil || n == "" {
				n = "unknown"
			}
			select {
			case networks <- n:
			case <-ctx.Done():
				return
			}
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
	network, session, epoch := "unknown", "", ""
	demands := map[string]*demand{}
	var generation uint64
	starts, deferred := 0, 0
	cancelAll := func() {
		for _, d := range demands {
			if d.cancel != nil {
				d.cancel()
			}
		}
	}
	defer cancelAll()
	synchronize := func(active, next string, now time.Time) error {
		if active == session && next == network && (epoch != "" || active == "" || next == "unknown") {
			return nil
		}
		value, err := c.repo.activateNetwork(active, next, now)
		if err != nil {
			return err
		}
		cancelAll()
		generation++
		demands = map[string]*demand{}
		session, network, epoch = active, next, value
		c.mu.Lock()
		c.epoch = epoch
		c.mu.Unlock()
		return nil
	}
	apply := func(p probeResult, now time.Time) error {
		if p.enriched {
			return c.repo.enrichPublication(p.attempt, p.value, now)
		}
		return c.repo.finish(p.attempt, p.value, now, true)
	}
	for {
		select {
		case <-ctx.Done():
			return
		case <-c.stop:
			return
		case ack := <-c.reset:
			cancelAll()
			generation++
			demands = map[string]*demand{}
			c.mu.Lock()
			c.intake = map[string]Traffic{}
			c.mu.Unlock()
			for len(c.requests) > 0 {
				req := <-c.requests
				req.Reply <- fmt.Errorf("route request reset")
			}
			close(ack)
		case next := <-networks:
			if err := synchronize(c.session(), next, time.Now().UTC()); err != nil {
				lastError = err.Error()
			}
		case req := <-c.requests:
			if c.config.Engine == "off" {
				req.Reply <- fmt.Errorf("route engine disabled")
				continue
			}
			if err := synchronize(c.session(), network, time.Now().UTC()); err != nil {
				req.Reply <- err
				continue
			}
			b, err := c.repo.observedBinding(session, network, epoch, req.ChunkID)
			if err != nil {
				req.Reply <- err
				continue
			}
			key := b.key()
			d := demands[key]
			if d == nil {
				if len(demands) >= c.config.MaxPending {
					req.Reply <- fmt.Errorf("route queue full")
					continue
				}
				d = &demand{binding: b, first: time.Now(), buckets: map[int64]int64{}}
				demands[key] = d
			}
			if !d.running {
				d.manual = true
			}
			d.last = time.Now()
			req.Reply <- nil
		case p := <-updates:
			d := demands[p.key]
			if d == nil || d.generation != p.generation {
				if !p.enriched {
					if err := c.repo.finish(p.attempt, p.value, time.Now().UTC(), false); err != nil {
						lastError = err.Error()
					}
				}
				continue
			}
			d.pending = append(d.pending, p)
		case now := <-ticker.C:
			if err := synchronize(c.session(), network, now); err != nil {
				lastError = err.Error()
				continue
			}
			c.mu.Lock()
			incoming := c.intake
			c.intake = map[string]Traffic{}
			deferred += c.deferred
			c.deferred = 0
			c.mu.Unlock()
			for _, f := range incoming {
				if f.Session != session || f.NetworkEpoch != epoch || session == "" {
					continue
				}
				b := routeBinding{Session: session, Network: network, Epoch: epoch, Target: target{f.IP, f.Protocol, f.Port}}
				key := b.key()
				d := demands[key]
				if d == nil {
					if len(demands) >= c.config.MaxPending {
						deferred++
						continue
					}
					d = &demand{binding: b, first: f.At, buckets: map[int64]int64{}}
					demands[key] = d
				}
				d.last = f.At
				d.buckets[f.At.Unix()] = safeAdd(d.buckets[f.At.Unix()], f.Bytes)
			}
			for _, d := range demands {
				for len(d.pending) > 0 && !now.Before(d.retry) {
					p := d.pending[0]
					if err := apply(p, now); err != nil {
						lastError = err.Error()
						d.retry = now.Add(time.Second)
						break
					}
					d.pending = d.pending[1:]
					d.retry = time.Time{}
					if !p.enriched {
						d.running = false
						d.state = p.value.Status
					} else {
						d.cancel = nil
					}
				}
			}
			views := map[string]ledger{}
			if session != "" && epoch != "" {
				for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
					b := routeBinding{Session: session, Network: network, Epoch: epoch, Target: target{ip, "tcp", 443}}
					l, err := readLedger(c.repo.app, b, now)
					if err != nil {
						lastError = err.Error()
					} else {
						views[family(b.Target)] = l
					}
				}
			}
			ranked := []*demand{}
			for key, d := range demands {
				l, ok := views[family(d.binding.Target)]
				if !ok {
					continue
				}
				tried := l.methods(d.binding)
				pendingComparison := len(tried) > 0 && len(tried) < len(probeMethods(d.binding.Target))
				useful := l.useful(d.binding, now) || l.automaticDone(d.binding)
				if now.Sub(d.last) > time.Minute && !d.running && !d.manual && !pendingComparison && len(d.pending) == 0 {
					delete(demands, key)
					continue
				}
				if !d.running && len(d.pending) == 0 && (d.manual || (!useful && len(tried) < len(probeMethods(d.binding.Target)) && (pendingComparison || d.qualified(now, c.config.MinBytes)))) {
					ranked = append(ranked, d)
				} else if !d.running {
					d.state = "low_activity"
					if useful {
						d.state = "useful_path_saved"
					} else if len(tried) >= len(probeMethods(d.binding.Target)) {
						d.state = "comparison_finished"
					}
				}
			}
			sort.Slice(ranked, func(i, j int) bool {
				a, b := ranked[i], ranked[j]
				if a.manual != b.manual {
					return a.manual
				}
				ap := len(views[family(a.binding.Target)].methods(a.binding)) > 0
				bp := len(views[family(b.binding.Target)].methods(b.binding)) > 0
				if ap != bp {
					return ap
				}
				wa, wb := a.weight(now), b.weight(now)
				if wa != wb {
					return wa > wb
				}
				return a.first.Before(b.first)
			})
			if c.config.Engine != "off" && len(slots) == 0 {
				for _, d := range ranked {
					a, err := c.repo.reserve(d.binding, d.manual, now)
					if err != nil {
						lastError = err.Error()
						break
					}
					if a.Reason != "" {
						d.state = a.Reason
						if a.Reason != "paced" {
							d.manual = false
						}
						continue
					}
					generation++
					d.generation = generation
					d.running = true
					d.manual = false
					d.state = "probing"
					starts++
					slots <- struct{}{}
					d.cancel = c.launch(ctx, &workers, slots, updates, enricher, d.generation, a)
					break
				}
			}
			stats := Stats{Session: session, Network: network, NetworkEpoch: epoch, Engine: c.config.Engine, UpdatedMS: now.UnixMilli(), Running: len(slots), Starts: starts, Deferred: deferred, LastError: lastError, Pending: max(0, len(ranked)-len(slots)), Targets: []TargetStatus{}}
			targets := map[string]TargetStatus{}
			for _, l := range views {
				stats.Attempts = max(stats.Attempts, l.attempts+l.manual)
				stats.AttemptsRemaining = max(0, c.config.MaxAttempts-l.attempts)
				stats.ManualRemaining = max(0, c.config.ManualAttempts-l.manual)
				stats.UsefulPaths = max(stats.UsefulPaths, l.paths())
				stats.EvidenceBytes = max(stats.EvidenceBytes, l.bytes)
				for _, run := range l.runs {
					if run.Session == session && run.Scope == l.scope && run.NetworkEpoch == epoch {
						state := run.Class
						if state == "" || run.Status == "cancelled" || run.Status == "interrupted" {
							state = run.Status
						}
						targets[run.BindingKey] = TargetStatus{run.DestinationIP, run.Protocol, run.DestinationPort, state}
					}
				}
			}
			for _, d := range demands {
				if c.config.Engine == "off" {
					d.state = "disabled"
				}
				stats.RecentBytes = safeAdd(stats.RecentBytes, d.weight(now))
				targets[d.binding.Target.binding()] = TargetStatus{d.binding.Target.IP, d.binding.Target.Protocol, d.binding.Target.Port, d.state}
			}
			for _, status := range targets {
				stats.Targets = append(stats.Targets, status)
			}
			sort.Slice(stats.Targets, func(i, j int) bool {
				a, b := stats.Targets[i], stats.Targets[j]
				return target{a.IP, a.Protocol, a.Port}.binding() < target{b.IP, b.Protocol, b.Port}.binding()
			})
			c.mu.Lock()
			c.stats = stats
			c.mu.Unlock()
		}
	}
}

// A cancellation retains the sole physical lease through process/pipe drain,
// enrichment and pacing. Reset changes generation but never frees this lease.
func (c *Coordinator) launch(ctx context.Context, workers *sync.WaitGroup, slots chan struct{}, updates chan<- probeResult, enricher *interfaceEnricher, generation uint64, a admission) context.CancelFunc {
	job, cancel := context.WithCancel(ctx)
	workers.Add(1)
	go func() {
		defer workers.Done()
		defer func() { <-slots; cancel() }()
		s := c.probe.Run(job, a.Binding.Target, probePlan{Method: a.Method, Sequence: a.Sequence, SourcePort: a.SourcePort})
		if job.Err() != nil {
			s.Status = "cancelled"
		}
		s.Attempt = a.Attempt
		s.Revision = 1
		if s.Method == "" {
			s.Method = a.Method
		}
		if s.Finished.IsZero() {
			s.Finished = time.Now().UTC()
		}
		emit := func(s snapshot, enriched bool) {
			select {
			case updates <- probeResult{key: a.Binding.key(), generation: generation, attempt: a, value: s, enriched: enriched}:
			case <-ctx.Done():
			}
		}
		emit(s, false)
		if job.Err() == nil && classifyRouteEvidence(s, a.Binding.Target, nil).Class == "useful_path" {
			if c.enrich != nil {
				s = c.enrich(job, s)
			} else {
				s = enricher.enrich(job, s)
			}
			s.Revision = 2
			emit(s, true)
		}
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
		}
	}()
	return cancel
}

func (r evidenceStore) observedBinding(session, network, epoch, chunkID string) (routeBinding, error) {
	rec, err := r.app.FindRecordById("traffic_chunks", chunkID)
	if err != nil || session == "" || rec.GetString("session") != session || rec.GetString("network_epoch") != epoch {
		return routeBinding{}, fmt.Errorf("select observed traffic in the active network epoch")
	}
	chunk, err := data.Decode[data.TrafficChunk](rec)
	if err != nil {
		return routeBinding{}, err
	}
	ip, err := netip.ParseAddr(chunk.DestinationIP)
	if err != nil || (chunk.Protocol != "tcp" && chunk.Protocol != "udp") || chunk.DestinationPort < 1 || chunk.DestinationPort > 65535 {
		return routeBinding{}, fmt.Errorf("unsupported destination binding")
	}
	return routeBinding{Session: session, Network: network, Epoch: epoch, Target: target{ip.Unmap().String(), chunk.Protocol, chunk.DestinationPort}}, nil
}
