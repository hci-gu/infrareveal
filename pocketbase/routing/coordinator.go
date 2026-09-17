// Package routing collects a finite set of useful gateway route approximations.
package routing

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

type TargetStatus struct {
	IP       string `json:"destination_ip"`
	Protocol string `json:"protocol"`
	Port     int    `json:"destination_port"`
	State    string `json:"state"`
}
type Stats struct {
	CoverageRunning      int              `json:"coverage_running"`
	ReachedByteCoverage  float64          `json:"reached_byte_coverage"`
	LocatedByteCoverage  float64          `json:"located_byte_coverage"`
	HopCoverage          float64          `json:"hop_coverage"`
	RecentBytes          int64            `json:"recent_bytes"`
	MeasuredByteCoverage float64          `json:"measured_byte_coverage"`
	Pending              int              `json:"pending"`
	Running              int              `json:"running"`
	Starts               int              `json:"starts"`
	CacheHits            int              `json:"cache_hits"`
	Deferred             int              `json:"deferred"`
	Failures             int              `json:"failures"`
	OldestWaitMS         int64            `json:"oldest_wait_ms"`
	LastError            string           `json:"last_error"`
	Network              string           `json:"network_context"`
	Session              string           `json:"session"`
	UpdatedAt            string           `json:"updated_at"`
	Engine               string           `json:"engine"`
	UsefulPaths          int              `json:"useful_paths"`
	UniqueUseful         int              `json:"unique_useful_bindings"`
	NoGain               int              `json:"no_gain_attempts"`
	Suppressed           int              `json:"suppressed_attempts"`
	Duplicates           int              `json:"duplicate_publications_avoided"`
	EvidenceBytes        int              `json:"evidence_bytes_written"`
	Attempts             int              `json:"attempts"`
	RouteRows            int              `json:"route_rows_written"`
	UsefulPerAttempt     float64          `json:"useful_paths_per_attempt"`
	UsefulPerKiB         float64          `json:"useful_paths_per_kib"`
	AttemptsRemaining    int              `json:"budget_remaining"`
	ManualRemaining      int              `json:"manual_remaining"`
	Targets              []TargetStatus   `json:"targets"`
	Access               []accessEvidence `json:"access_context"`
}
type demand struct {
	target                         target
	session, key                   string
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
	terminal   bool
}
type manualRequest struct {
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
	requests       chan manualRequest
	repo           repository
	config         Config
	probe          prober
	session        func() string
	network        func() (string, error)
}

func Start(ctx context.Context, app core.App, geo *geoip2.Reader, session func() string, config Config) *Coordinator {
	version := "unknown"
	if f, e := os.Stat("./geoip/city.mmdb"); e == nil {
		version = fmt.Sprintf("%d/%d", f.Size(), f.ModTime().Unix())
	}
	var engine prober = coverageProbe{deadline: config.QualityDeadline}
	if config.Engine == "legacy" {
		engine = commandProbe{deadline: config.QualityDeadline}
	}
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), requests: make(chan manualRequest, 10), repo: repository{app: app, geo: geo, geoVersion: version, locations: map[string]*Location{}, config: config}, config: config, probe: engine, session: session, network: networkContext}
	go c.run(ctx)
	return c
}
func (c *Coordinator) Observe(f Flow) {
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
	return s
}
func (c *Coordinator) Reset() {
	ack := make(chan struct{})
	select {
	case c.reset <- ack:
		select {
		case <-ack:
		case <-c.done:
		}
	case <-c.done:
	}
}
func (c *Coordinator) Measure(ctx context.Context, flowID string) error {
	req := manualRequest{flowID, make(chan error, 1)}
	select {
	case c.requests <- req:
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	}
	select {
	case e := <-req.Reply:
		return e
	case <-ctx.Done():
		return ctx.Err()
	case <-c.done:
		return fmt.Errorf("route discovery stopped")
	}
}
func (c *Coordinator) ExtendBudget() error { return c.repo.extend(c.session()) }
func (c *Coordinator) run(ctx context.Context) {
	defer close(c.done)
	c.repo.config = c.config
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	updates := make(chan progress, 4)
	enricher := newInterfaceEnricher()
	defer enricher.close()
	var workers sync.WaitGroup
	defer workers.Wait()
	// A cancelled child retains its lease until pipes and process have exited.
	slots := make(chan struct{}, 1)
	networks := make(chan string, 1)
	go func() {
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
	lastPrune := time.Now()
	lastDone := time.Time{}
	lastError := ""
	cancelAll := func() {
		for _, d := range demands {
			if d.cancel != nil {
				d.cancel()
			}
		}
	}
	defer cancelAll()
	apply := func(d *demand, p progress, now time.Time) bool {
		s := p.value
		next, e := c.repo.publish(d.key, network, d.session, d.target, d.cache, s, s.Status, "measured", now)
		if e != nil {
			lastError = e.Error()
			d.retryPublication = now.Add(time.Second)
			d.pending = &p
			return false
		}
		d.cache = next
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
		case ack := <-c.reset:
			cancelAll()
			generation++
			demands = map[string]*demand{}
			counters = map[string]counter{}
			c.mu.Lock()
			c.intake = map[string]Flow{}
			c.mu.Unlock()
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
			if c.config.Engine == "off" {
				req.Reply <- fmt.Errorf("route engine disabled")
				continue
			}
			f, e := c.repo.app.FindRecordById("flows", req.FlowID)
			if e != nil || f.GetString("session") != c.session() {
				req.Reply <- fmt.Errorf("select an observed flow in the active session")
				continue
			}
			t := target{f.GetString("destination_ip"), f.GetString("protocol"), f.GetInt("destination_port")}
			ip, parseErr := netip.ParseAddr(t.IP)
			if parseErr != nil || (t.Protocol != "tcp" && t.Protocol != "udp") || t.Port < 1 || t.Port > 65535 {
				req.Reply <- fmt.Errorf("unsupported flow")
				continue
			}
			t.IP = ip.Unmap().String()
			key := t.key(network)
			d := demands[key]
			if d == nil {
				if len(demands) >= c.config.MaxPending {
					req.Reply <- fmt.Errorf("route queue full")
					continue
				}
				d = &demand{target: t, session: c.session(), key: key, first: time.Now(), buckets: map[int64]int64{}}
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
			if active != session {
				if err := c.repo.activateNetwork(active, network, now); err != nil {
					lastError = err.Error()
					continue
				}
				cancelAll()
				generation++
				demands = map[string]*demand{}
				counters = map[string]counter{}
				session = active
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
					d = &demand{target: t, session: active, key: key, first: f.At, last: f.At, buckets: map[int64]int64{}}
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
			admissionBudget := sessionBudget{}
			if active != "" {
				_, loaded, budgetErr := loadSessionBudget(c.repo.app, active)
				if budgetErr != nil {
					lastError = budgetErr.Error()
				} else {
					admissionBudget = loaded
				}
			}
			for key, d := range demands {
				comparisonPending := admissionBudget.Targets[key].comparisonPending(d.target)
				if d.pending != nil && !now.Before(d.retryPublication) {
					apply(d, *d.pending, now)
				}
				if now.Sub(d.last) > time.Minute && !d.running && !d.manual && !comparisonPending && d.pending == nil {
					delete(demands, key)
					continue
				}
				if !d.loaded {
					e, err := c.repo.load(key)
					if err != nil {
						lastError = err.Error()
						continue
					}
					d.cache = e
					// Old v2 cache entries can contain only an initial segment plus
					// an endpoint. Reapply today's evidence gate before reuse/counting.
					if classifyRouteEvidence(d.cache.Best, d.target, nil).Class != "useful_path" {
						d.cache = cacheEntry{}
					}
					d.loaded = true
				}
				if !d.bound && d.cache.Best.Attempt != "" && now.Before(d.cache.ValidUntil) {
					_, err := c.repo.publish(key, network, active, d.target, d.cache, d.cache.Best, "cached", "cache", now)
					if err != nil {
						lastError = err.Error()
						continue
					}
					d.bound = true
					hits++
				}
				if !d.running && d.pending == nil && (d.manual || comparisonPending || d.qualified(now, c.config.MinBytes)) {
					ranked = append(ranked, d)
				} else if !d.running {
					v := admissionBudget.Targets[key]
					switch {
					case v.Useful:
						d.state = "useful_path_saved"
					case v.Attempts >= len(qualityMethods(d.target)):
						d.state = "comparison_finished"
					default:
						d.state = "low_activity"
					}
				}
			}
			sort.Slice(ranked, func(i, j int) bool {
				a, b := ranked[i], ranked[j]
				if a.manual != b.manual {
					return a.manual
				}
				ac, bc := admissionBudget.Targets[a.key].comparisonPending(a.target), admissionBudget.Targets[b.key].comparisonPending(b.target)
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
					a, err := c.repo.reserve(active, network, d.target, c.config, d.manual, now)
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
					job, cancel := context.WithCancel(ctx)
					d.cancel = cancel
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
							case updates <- progress{key, g, s, terminal}:
							case <-ctx.Done():
							}
						}
						s := c.probe.Run(job, t, probePlan{Quality: true, Method: a.Method, Sequence: a.Sequence, SourcePort: a.SourcePort}, func(s snapshot) {
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
					}(d.key, d.generation, d.target, a)
					break
				}
			}
			b := sessionBudget{}
			if active != "" {
				_, loaded, e := loadSessionBudget(c.repo.app, active)
				if e == nil {
					b = loaded
				} else {
					lastError = e.Error()
				}
			}
			stats := Stats{Network: network, Session: active, Engine: c.config.Engine, Running: len(slots), Starts: starts, CacheHits: hits, Failures: failures, Deferred: deferred, LastError: lastError, UpdatedAt: date(now), UsefulPaths: b.Snapshots, NoGain: b.NoGain, Duplicates: b.Duplicates, EvidenceBytes: b.Bytes, AttemptsRemaining: max(0, c.config.MaxAttempts+b.ExtraAttempts-b.Attempts), ManualRemaining: max(0, c.config.ManualAttempts-b.Manual), Targets: []TargetStatus{}}
			for _, v := range b.Targets {
				if v.Useful {
					stats.UniqueUseful++
				}
			}
			var measured, reached, located int64
			for _, d := range demands {
				if c.config.Engine == "off" {
					d.state = "disabled"
				}
				weight := d.weight(now)
				stats.RecentBytes += weight
				if d.cache.Best.Attempt != "" && now.Before(d.cache.ValidUntil) {
					measured += weight
					if d.cache.Best.Reached {
						reached += weight
					}
					if d.cache.Best.located() > 0 {
						located += weight
					}
				}
				stats.Targets = append(stats.Targets, TargetStatus{d.target.IP, d.target.Protocol, d.target.Port, d.state})
				if d.state == "probing" {
					continue
				}
				if d.state == "negative_cache" || d.state == "visibility_paused" || d.state == "useful_path_saved" || d.state == "comparison_finished" {
					stats.Suppressed++
				}
			}
			// Outcomes remain explainable after an idle binding leaves demand memory.
			if active != "" {
				outcomes, err := c.repo.app.FindRecordsByFilter("route_outcomes", "session={:s}", "", 120, 0, dbx.Params{"s": active})
				if err == nil {
					seen := map[string]bool{}
					for _, v := range stats.Targets {
						seen[target{v.IP, v.Protocol, v.Port}.binding()] = true
					}
					for _, rec := range outcomes {
						var v outcome
						data, _ := json.Marshal(rec.Get("value"))
						if json.Unmarshal(data, &v) == nil && !seen[target{v.IP, v.Protocol, v.Port}.binding()] {
							stats.Targets = append(stats.Targets, TargetStatus{v.IP, v.Protocol, v.Port, v.Class})
						}
					}
				}
			}
			stats.Attempts = b.Attempts + b.Manual
			stats.RouteRows = b.Snapshots
			stats.UsefulPerAttempt = float64(stats.UniqueUseful) / float64(max(1, stats.Attempts))
			stats.UsefulPerKiB = float64(stats.UniqueUseful) * 1024 / float64(max(1, b.Bytes))
			sort.Slice(stats.Targets, func(i, j int) bool { return stats.Targets[i].IP < stats.Targets[j].IP })
			den := float64(max(1, stats.RecentBytes))
			stats.MeasuredByteCoverage = float64(measured) / den
			stats.ReachedByteCoverage = float64(reached) / den
			stats.LocatedByteCoverage = float64(located) / den
			stats.Pending = max(0, len(ranked)-len(slots))
			for _, f := range []string{"ipv4", "ipv6"} {
				n := networkBudget{}
				_, e := loadState(c.repo.app, "network:"+network+":"+f, &n)
				if e == nil && len(n.Access.Witnesses) >= 3 {
					stats.Access = append(stats.Access, n.Access)
				}
			}
			c.mu.Lock()
			c.stats = stats
			c.mu.Unlock()
			if now.Sub(lastPrune) > time.Minute {
				if e := c.repo.prune(now); e != nil {
					log.Printf("route retention: %v", e)
				}
				lastPrune = now
			}
		}
	}
}
