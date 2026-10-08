// Package routing collects a finite set of useful gateway route approximations.
package routing

import (
	"context"
	"fmt"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase/core"
)

type demand struct {
	binding                        routeBinding
	first, last                    time.Time
	buckets                        map[int64]int64
	cache                          cacheEntry
	loaded, bound, running, manual bool
	state                          string
	generation                     uint64
	cancel                         context.CancelFunc
	retryPublication               time.Time
	pending                        *progress
}

func (d *demand) weight(now time.Time) int64 {
	var total int64
	for sec, n := range d.buckets {
		if sec < now.Add(-30*time.Second).Unix() {
			delete(d.buckets, sec)
		} else {
			total += n
		}
	}
	return total
}
func (d *demand) qualified(now time.Time, minimum int64) bool {
	if d.weight(now) >= minimum {
		return true
	}
	var first, last int64
	count := 0
	for sec, n := range d.buckets {
		if n > 0 {
			count++
			if first == 0 || sec < first {
				first = sec
			}
			if sec > last {
				last = sec
			}
		}
	}
	return count >= 3 && last-first >= 10
}

type counter struct {
	bytes int64
	at    time.Time
}
type progress struct {
	key        string
	generation uint64
	value      snapshot
	attempt    admission
	terminal   bool
}
type manualRequest struct {
	Extend bool
	FlowID string
	Reply  chan error
}
type Coordinator struct {
	mu             sync.Mutex
	intake         map[string]Flow
	intakeDeferred int
	stats          Stats
	reset          chan chan struct{}
	done           chan struct{}
	stop           chan struct{}
	closeOnce      sync.Once
	requests       chan manualRequest
	repo           evidenceStore
	config         Config
	probe          prober
	session        func() string
	network        func() (string, error)
}

func Start(ctx context.Context, app core.App, geo *geoip2.Reader, session func() string, config Config) *Coordinator {
	var engine prober = scamperProbe{deadline: config.ProbeDeadline}
	if config.Engine == "legacy" {
		engine = tracerouteProbe{deadline: config.ProbeDeadline}
	}
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), stop: make(chan struct{}), requests: make(chan manualRequest, 10), repo: newEvidenceStore(app, geo, config), config: config, probe: engine, session: session, network: networkContext}
	go c.run(ctx)
	return c
}

// Close cancels work and waits until subprocesses, their pipes, and lookup
// workers have exited. A timed-out caller can call Close again to await the same
// completion; shared resources must remain available until it succeeds.
func (c *Coordinator) Close(ctx context.Context) error {
	c.closeOnce.Do(func() { close(c.stop) })
	select {
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (c *Coordinator) Observe(f Flow) {
	select {
	case <-c.stop:
		return
	default:
	}
	ip, e := netip.ParseAddr(f.IP)
	if e != nil || f.Session == "" || (f.Protocol != "tcp" && f.Protocol != "udp") || f.Port < 1 || f.Port > 65535 {
		return
	}
	f.IP = ip.Unmap().String()
	c.mu.Lock()
	defer c.mu.Unlock()
	key := f.Session + "|" + f.ID
	if _, ok := c.intake[key]; !ok && len(c.intake) >= c.config.MaxPending*16 {
		c.intakeDeferred++
		return
	}
	if previous, ok := c.intake[key]; ok && previous.Baseline {
		f.Baseline = true
	}
	c.intake[key] = f
}
func (c *Coordinator) Status() Stats {
	c.mu.Lock()
	defer c.mu.Unlock()
	s := c.stats
	s.Targets = append([]TargetStatus(nil), s.Targets...)
	s.Access = append([]accessEvidence(nil), s.Access...)
	for i := range s.Access {
		s.Access[i].Witnesses = append([]accessWitness(nil), s.Access[i].Witnesses...)
		s.Access[i].Prefix = append([]accessPosition(nil), s.Access[i].Prefix...)
		for j := range s.Access[i].Prefix {
			s.Access[i].Prefix[j].Addresses = append([]string(nil), s.Access[i].Prefix[j].Addresses...)
		}
	}
	return s
}

// Reset acknowledges after discarding all accepted intake, pending publication,
// and demand state. Late results retain their physical lease but their generation
// can no longer commit. Callers quiesce observation producers before resetting.
func (c *Coordinator) Reset() {
	_ = c.ResetContext(context.Background())
}

// ResetContext provides the same commit fence as Reset. A timeout is not an
// acknowledgement: callers must abort deletion and may request reset again.
func (c *Coordinator) ResetContext(ctx context.Context) error {
	ack := make(chan struct{})
	select {
	case c.reset <- ack:
		select {
		case <-ack:
			return nil
		case <-c.done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	case <-c.done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (c *Coordinator) Measure(ctx context.Context, flowID string) error {
	return c.request(ctx, manualRequest{FlowID: flowID})
}

func (c *Coordinator) request(ctx context.Context, req manualRequest) error {
	req.Reply = make(chan error, 1)
	select {
	case c.requests <- req:
	case <-c.stop:
		return fmt.Errorf("route discovery stopped")
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	}
	select {
	case e := <-req.Reply:
		return e
	case <-c.stop:
		return fmt.Errorf("route discovery stopped")
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	}
}
func (c *Coordinator) ExtendBudget() error {
	return c.request(context.Background(), manualRequest{Extend: true})
}
func (c *Coordinator) run(parent context.Context) {
	ctx, cancel := context.WithCancel(parent)
	defer close(c.done)
	c.repo.config = c.config
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	updates := make(chan progress, 4)
	enricher := newInterfaceEnricher(c.config.ASNDBPath)
	defer enricher.close()
	var workers sync.WaitGroup
	defer func() { cancel(); workers.Wait() }()
	// A cancelled child retains its lease until pipes and process have exited.
	slots := make(chan struct{}, 1)
	networks := make(chan string, 1)
	workers.Add(1)
	go func() {
		defer workers.Done()
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		for {
			n, e := c.network()
			if e == nil {
				select {
				case networks <- n:
				case <-ctx.Done():
					return
				}
			}
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
			}
		}
	}()
	// A failed context lookup must not replenish persisted limits on restart.
	network := "unknown"
	demands := map[string]*demand{}
	counters := map[string]counter{}
	session := ""
	var generation uint64
	starts, hits, failures, deferred := 0, 0, 0, 0
	lastDone := time.Time{}
	lastError := ""
	stateChanged := false
	cancelAll := func() {
		for _, d := range demands {
			if d.cancel != nil {
				d.cancel()
			}
		}
	}
	defer cancelAll()
	synchronizeSession := func(active string, now time.Time) error {
		if active == session {
			return nil
		}
		if err := c.repo.activateNetwork(active, network, now); err != nil {
			return err
		}
		cancelAll()
		generation++
		demands = map[string]*demand{}
		counters = map[string]counter{}
		session = active
		return nil
	}
	apply := func(d *demand, p progress, now time.Time) bool {
		s := p.value
		next, e := c.repo.publish(publication{Binding: p.attempt.Binding, Cache: d.cache, Snapshot: s, Provenance: "measured"}, now)
		if e != nil {
			lastError = e.Error()
			d.retryPublication = now.Add(time.Second)
			d.pending = &p
			return false
		}
		d.cache = next
		if next.Best.Attempt == s.Attempt && s.Attempt != "" {
			// This successful publication already bound the retained evidence to
			// this session. Do not republish it as a synthetic cache hit next tick.
			d.bound = true
		}
		stateChanged = true
		d.pending = nil
		d.retryPublication = time.Time{}
		if p.terminal {
			d.running = false
			d.cancel = nil
			lastDone = now
			d.state = s.Status
			if s.Status == "failed" {
				failures++
			}
			if s.Error != "" {
				lastError = s.Error
			}
		}
		return true
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
			counters = map[string]counter{}
			c.mu.Lock()
			c.intake = map[string]Flow{}
			c.mu.Unlock()
			// Requests already queued at the reset seam must not revive work
			// accepted for the old generation after the acknowledgement.
			for len(c.requests) > 0 {
				req := <-c.requests
				req.Reply <- fmt.Errorf("route request reset")
			}
			close(ack)
		case next := <-networks:
			if next == network {
				continue
			}
			if e := c.repo.activateNetwork(c.session(), next, time.Now().UTC()); e != nil {
				lastError = e.Error()
				continue
			}
			cancelAll()
			generation++
			demands = map[string]*demand{}
			network = next
		case req := <-c.requests:
			if req.Extend {
				req.Reply <- c.repo.extend(c.session())
				continue
			}
			if c.config.Engine == "off" {
				req.Reply <- fmt.Errorf("route engine disabled")
				continue
			}
			active := c.session()
			if err := synchronizeSession(active, time.Now().UTC()); err != nil {
				req.Reply <- err
				continue
			}
			binding, e := c.repo.observedBinding(active, network, req.FlowID)
			if e != nil {
				req.Reply <- e
				continue
			}
			key := binding.key()
			d := demands[key]
			if d == nil {
				if len(demands) >= c.config.MaxPending {
					req.Reply <- fmt.Errorf("route queue full")
					continue
				}
				d = &demand{binding: binding, first: time.Now(), buckets: map[int64]int64{}}
				demands[key] = d
			}
			if d.running || d.manual {
				req.Reply <- nil
				continue
			}
			d.manual = true
			d.last = time.Now()
			req.Reply <- nil
		case p := <-updates:
			d := demands[p.key]
			if d == nil || d.generation != p.generation {
				continue
			}
			apply(d, p, time.Now().UTC())
		case now := <-ticker.C:
			active := c.session()
			if err := synchronizeSession(active, now); err != nil {
				lastError = err.Error()
				continue
			}
			c.mu.Lock()
			incoming := c.intake
			deferred += c.intakeDeferred
			c.intakeDeferred = 0
			c.intake = map[string]Flow{}
			c.mu.Unlock()
			for id, f := range incoming {
				if f.Session != active || active == "" {
					continue
				}
				t := target{f.IP, f.Protocol, f.Port}
				key := t.key(network)
				d := demands[key]
				if d == nil {
					if len(demands) >= c.config.MaxPending {
						deferred++
						continue
					}
					d = &demand{binding: routeBinding{Session: active, Network: network, Target: t}, first: f.At, last: f.At, buckets: map[int64]int64{}}
					demands[key] = d
				}
				previous, exists := counters[id]
				if !exists && len(counters) >= c.config.MaxPending*16 {
					deferred++
					continue
				}
				delta := int64(0)
				if !exists && !f.Baseline {
					delta = f.Bytes
				}
				if exists {
					delta = max(0, f.Bytes-previous.bytes)
				}
				counters[id] = counter{f.Bytes, f.At}
				d.last = f.At
				d.buckets[f.At.Unix()] += delta
			}
			for id, v := range counters {
				if now.Sub(v.at) > time.Minute {
					delete(counters, id)
				}
			}
			ranked := []*demand{}
			// Qualification selects a bounded comparison, not just its first
			// process. Do not require another traffic burst after a slow attempt.
			view, err := c.repo.readDiscovery(active, network, now)
			if err != nil {
				lastError = err.Error()
				continue
			}
			stateChanged = false
			for key, d := range demands {
				progress := view.progress(d.binding)
				comparisonPending := progress.ComparisonPending
				if d.pending != nil && !now.Before(d.retryPublication) {
					apply(d, *d.pending, now)
				}
				if now.Sub(d.last) > time.Minute && !d.running && !d.manual && !comparisonPending && d.pending == nil {
					delete(demands, key)
					continue
				}
				if !d.loaded {
					e, err := c.repo.reusable(d.binding)
					if err != nil {
						lastError = err.Error()
						continue
					}
					d.cache = e
					d.loaded = true
				}
				if !d.bound && d.cache.Best.Attempt != "" && now.Before(d.cache.ValidUntil) {
					_, err := c.repo.bindCached(d.binding, d.cache, now)
					if err != nil {
						lastError = err.Error()
						continue
					}
					d.bound = true
					stateChanged = true
					hits++
				}
				savedUseful := progress.Useful || (d.bound && d.cache.Best.Attempt != "" && now.Before(d.cache.ValidUntil))
				eligible := d.manual || (!savedUseful && (comparisonPending || (progress.AutomaticAllowed && d.qualified(now, c.config.MinBytes))))
				if !d.running && d.pending == nil && eligible {
					ranked = append(ranked, d)
				} else if !d.running {
					d.state = progress.IdleState
					if savedUseful {
						d.state = "useful_path_saved"
					}
				}
			}
			sort.Slice(ranked, func(i, j int) bool {
				a, b := ranked[i], ranked[j]
				if a.manual != b.manual {
					return a.manual
				}
				ac, bc := view.progress(a.binding).ComparisonPending, view.progress(b.binding).ComparisonPending
				if ac != bc {
					return ac
				}
				wa, wb := a.weight(now), b.weight(now)
				if wa != wb {
					return wa > wb
				}
				return a.first.Before(b.first)
			})
			if len(ranked) > 10 {
				for _, d := range ranked[10:] {
					d.state = "not_selected"
				}
				ranked = ranked[:10]
			}
			if c.config.Engine != "off" && len(slots) == 0 && now.Sub(lastDone) >= 200*time.Millisecond {
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
					stateChanged = true
					slots <- struct{}{}
					d.cancel = c.launch(ctx, &workers, slots, updates, enricher, d.generation, a)
					break
				}
			}
			if stateChanged {
				if updated, err := c.repo.readDiscovery(active, network, now); err == nil {
					view = updated
				} else {
					lastError = err.Error()
				}
			}
			stats := view.stats
			stats.Running, stats.Starts, stats.CacheHits = len(slots), starts, hits
			stats.Failures, stats.Deferred, stats.LastError = failures, deferred, lastError
			stats = stats.withDemands(demands, now, c.config.Engine == "off")
			stats.Pending = max(0, len(ranked)-len(slots))
			c.mu.Lock()
			c.stats = stats
			c.mu.Unlock()

		}
	}
}

// launch holds the physical worker lease through cancellation, output drain,
// and the pacing interval. A reset may discard its messages but cannot reuse
// the lease until this function's child exits.
func (c *Coordinator) launch(ctx context.Context, workers *sync.WaitGroup, slots chan struct{}, updates chan<- progress, enricher *interfaceEnricher, generation uint64, a admission) context.CancelFunc {
	job, cancel := context.WithCancel(ctx)

	workers.Add(1)
	go func(key string, g uint64, t target, a admission) {
		defer workers.Done()
		defer func() { <-slots; cancel() }()
		revision := 0
		lastProgress := time.Time{}
		emit := func(s snapshot, terminal bool) {
			revision++
			s.Attempt = a.Attempt
			s.Revision = revision
			if s.Method == "" {
				s.Method = a.Method
			}
			select {
			case updates <- progress{key: key, generation: g, value: s, attempt: a, terminal: terminal}:
			case <-ctx.Done():
			}
		}
		s := c.probe.Run(job, t, probePlan{Method: a.Method, Sequence: a.Sequence, SourcePort: a.SourcePort}, func(s snapshot) {
			if time.Since(lastProgress) >= time.Second {
				lastProgress = time.Now()
				emit(s, false)
			}
		})
		if s.Finished.IsZero() {
			s.Finished = time.Now().UTC()
		}
		if classifyRouteEvidence(s, t, nil).Class == "useful_path" {
			s = enricher.enrich(job, s)
		}
		emit(s, true)
		select {
		case <-time.After(200 * time.Millisecond):
		case <-ctx.Done():
		}
	}(a.Binding.key(), generation, a.Binding.Target, a)
	return cancel
}
