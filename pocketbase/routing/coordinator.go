package routing

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/oschwald/geoip2-golang"
	"github.com/pocketbase/pocketbase/core"
)

type Stats struct {
	CoverageRunning      int     `json:"coverage_running"`
	ReachedByteCoverage  float64 `json:"reached_byte_coverage"`
	LocatedByteCoverage  float64 `json:"located_byte_coverage"`
	HopCoverage          float64 `json:"hop_coverage"`
	RecentBytes          int64   `json:"recent_bytes"`
	MeasuredByteCoverage float64 `json:"measured_byte_coverage"`
	Pending              int     `json:"pending"`
	Running              int     `json:"running"`
	Starts               int     `json:"starts"`
	CacheHits            int     `json:"cache_hits"`
	Deferred             int     `json:"deferred"`
	Failures             int     `json:"failures"`
	OldestWaitMS         int64   `json:"oldest_wait_ms"`
	LastError            string  `json:"last_error"`
	Network              string  `json:"network_context"`
	UpdatedAt            string  `json:"updated_at"`
}
type demand struct {
	plan             probePlan
	target           target
	session, key     string
	first, last      time.Time
	buckets          map[int64]int64
	cache            cacheEntry
	loaded, bound    bool
	running          bool
	cancel           context.CancelFunc
	slow             bool
	generation       uint64
	retryPublication time.Time
}

func (d *demand) weight(now time.Time) int64 {
	var total int64
	for sec, n := range d.buckets {
		if sec < now.Add(-10*time.Second).Unix() {
			delete(d.buckets, sec)
		} else {
			total += n
		}
	}
	return total
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

type Coordinator struct {
	mu             sync.Mutex
	intake         map[string]Flow
	intakeDeferred int
	stats          Stats
	reset          chan chan struct{}
	done           chan struct{}
	repo           repository
	config         Config
	probe          prober
	session        func() string
	network        func() (string, error)
}

func Start(ctx context.Context, app core.App, geo *geoip2.Reader, session func() string, config Config) *Coordinator {
	version := "unknown"
	if file, err := os.Stat("./geoip/city.mmdb"); err == nil {
		version = fmt.Sprintf("%d/%d", file.Size(), file.ModTime().Unix())
	}
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), repo: repository{app: app, geo: geo, geoVersion: version, locations: map[string]*Location{}}, config: config, probe: discoveryProbe{fast: commandProbe{deadline: config.FastDeadline}, quality: coverageProbe{deadline: config.QualityDeadline}}, session: session, network: networkContext}
	go c.run(ctx)
	return c
}

// Observe only copies committed counters. Disk and process work never occurs
// on the conntrack caller. Repeated updates coalesce to their latest counter.
func (c *Coordinator) Observe(f Flow) {
	if _, err := netip.ParseAddr(f.IP); err != nil || f.Session == "" || (f.Protocol != "tcp" && f.Protocol != "udp") {
		return
	}
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
func (c *Coordinator) Status() Stats { c.mu.Lock(); defer c.mu.Unlock(); return c.stats }
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

func (c *Coordinator) run(ctx context.Context) {
	defer close(c.done)
	ticker := time.NewTicker(c.config.Interval)
	defer ticker.Stop()
	updates := make(chan progress, c.config.Workers*4)
	// A cancelled subprocess may still be draining pipes. Keep its worker
	// lease across resets and network/session changes until it actually exits.
	slots := make(chan struct{}, c.config.Workers)
	coverageSlots := make(chan struct{}, 1)
	var coverageUnavailableUntil time.Time
	networks := make(chan string, 1)
	go func() {
		timer := time.NewTicker(2 * time.Second)
		defer timer.Stop()
		for {
			key, err := c.network()
			if err == nil {
				select {
				case networks <- key:
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
	network := "unknown:" + hash(fmt.Sprint(time.Now().UnixNano()))
	demands := map[string]*demand{}
	counters := map[string]counter{}
	var generation uint64
	var starts, hits, failures, deferred int
	lastPrune := time.Now()
	lastLog := time.Now()
	lastSession := ""
	cancelAll := func() {
		for _, d := range demands {
			if d.cancel != nil {
				d.cancel()
			}
		}
	}
	defer cancelAll()
	save := func(d *demand, s snapshot, state, source string, now time.Time) bool {
		entry, err := c.repo.publish(d.key, network, d.session, d.target, d.cache, s, state, source, now)
		if err != nil {
			c.mu.Lock()
			c.stats.LastError = err.Error()
			c.mu.Unlock()
			d.retryPublication = now.Add(time.Second)
			log.Printf("route publication failed: %v", err)
			return false
		}
		d.cache = entry
		d.retryPublication = time.Time{}
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
			now := time.Now().UTC()
			if err := c.repo.invalidateSession(c.session(), network, now); err != nil {
				log.Printf("route network invalidation: %v", err)

				continue
			}
			cancelAll()
			generation++
			demands = map[string]*demand{}
			network = next
		case update := <-updates:
			d := demands[update.key]
			if d == nil || d.generation != update.generation {
				continue
			}
			now := time.Now().UTC()
			s := c.repo.enrich(update.value, d.target)
			if update.terminal {
				d.running = false
				d.cancel = nil
			}
			d.cache.Last = s
			if d.cache.Methods == nil {
				d.cache.Methods = map[string]snapshot{}
			}
			methodOld := d.cache.Methods[s.Method]
			methodTTL := time.Minute
			if methodOld.Reached {
				methodTTL = c.config.StaleTTL
			}
			if s.replies() > 0 && (now.Sub(methodOld.Measured) > methodTTL || betterSnapshot(methodOld, s)) {
				d.cache.Methods[s.Method] = s
			}
			old := d.cache.Best
			if s.replies() > 0 && (!now.Before(d.cache.ValidUntil) || betterSnapshot(old, s)) {
				d.cache.Best = s
				d.cache.FreshUntil = now.Add(time.Minute)
				d.cache.ValidUntil = now.Add(time.Minute)
				if s.Reached {
					d.cache.FreshUntil = now.Add(c.config.FreshTTL)
					d.cache.ValidUntil = now.Add(c.config.StaleTTL)
				}
			}
			if update.terminal {
				if s.Error != "" && s.Status != "cancelled" {
					c.mu.Lock()
					c.stats.LastError = s.Error
					c.mu.Unlock()
				}
				if d.slow {
					if s.Status == "cancelled" {
						d.cache.QualityNext = now.Add(2 * time.Second)
					} else {
						d.cache.QualityIndex++
						d.cache.QualityNext = now.Add(15 * time.Second)
						if d.cache.QualityIndex%3 == 0 {
							d.cache.QualityNext = now.Add(10 * time.Minute)
						}
						capabilityError := strings.ToLower(s.Error)
						if strings.Contains(capabilityError, "executable file not found") || strings.Contains(capabilityError, "operation not permitted") || strings.Contains(capabilityError, "permission denied") {
							coverageUnavailableUntil = now.Add(time.Minute)
						}
					}
				} else if d.cache.QualityNext.IsZero() {
					d.cache.QualityNext = now.Add(5 * time.Second)
				}
				if s.Status == "cancelled" {
					d.cache.RetryAt = now.Add(time.Second)
				} else if s.Reached {
					d.cache.Failures = 0
					d.cache.RetryAt = d.cache.FreshUntil
				} else {
					failures++
					d.cache.Failures++
					backoff := []time.Duration{15 * time.Second, time.Minute, 5 * time.Minute}[min(d.cache.Failures-1, 2)]
					d.cache.RetryAt = now.Add(backoff + time.Duration(starts%5)*time.Second)
				}
			}
			state := s.Status
			if d.cache.Best.Reached && !s.Reached {
				state = "refreshing"
				if update.terminal {
					state = "cached"
				}
			}
			source := "measured"
			if s.Method != "" && methodProtocol(s.Method) != d.target.Protocol {
				source = "alternate"
			}
			save(d, s, state, source, now)
		case now := <-ticker.C:
			active := c.session()
			if active != lastSession {
				cancelAll()
				generation++
				demands = map[string]*demand{}
				counters = map[string]counter{}
				lastSession = active
			}
			c.mu.Lock()
			incoming := c.intake
			deferred += c.intakeDeferred
			c.intakeDeferred = 0
			c.intake = map[string]Flow{}
			c.mu.Unlock()
			for id, f := range incoming {
				if active == "" || f.Session != active {
					continue
				}
				t := target{f.IP, f.Protocol, f.Port}
				key := t.key(network)
				d := demands[key]
				if d == nil {
					if len(demands) >= c.config.MaxPending {
						var victim *demand
						for _, candidate := range demands {
							if !candidate.running && (victim == nil || candidate.last.Before(victim.last)) {
								victim = candidate
							}
						}
						if victim != nil && now.Sub(victim.last) > 10*time.Second {
							delete(demands, victim.key)
						} else {
							deferred++
							continue
						}
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
					delta = f.Bytes - previous.bytes
					if delta < 0 {
						delta = 0
					}
				}
				counters[id] = counter{f.Bytes, f.At}
				d.last = f.At
				d.buckets[f.At.Unix()] += delta
			}
			for id, count := range counters {
				if now.Sub(count.at) > time.Minute {
					delete(counters, id)
				}
			}
			ranked := make([]*demand, 0, len(demands))
			var recentBytes, coveredBytes, reachedBytes, locatedBytes int64
			var hopCoverage float64
			for _, d := range demands {
				ranked = append(ranked, d)
				weight := d.weight(now)
				recentBytes += weight
				if d.cache.Best.replies() > 0 && now.Before(d.cache.ValidUntil) {
					coveredBytes += weight
					if d.cache.Best.Reached {
						reachedBytes += weight
					}
					if d.cache.Best.located() > 0 {
						locatedBytes += weight
					}
					hopCoverage += float64(weight) * d.cache.Best.coverage()
				}
			}
			sort.Slice(ranked, func(i, j int) bool {
				a, b := ranked[i].weight(now), ranked[j].weight(now)
				if a != b {
					return a > b
				}
				return ranked[i].key < ranked[j].key
			})
			important := map[string]bool{}
			var coveredPriority int64
			for _, d := range ranked {
				if len(important) > 0 && float64(coveredPriority) >= float64(recentBytes)*0.9 {
					break
				}
				important[d.key] = true
				coveredPriority += d.weight(now)
			}
			var queue []*demand
			running, background := 0, 0
			for key, d := range demands {
				weight := d.weight(now)
				if d.running {
					running++
					if d.slow {
						background++
					}
					continue
				}
				if now.Sub(d.last) > time.Minute {
					delete(demands, key)
					continue
				}
				if now.Before(d.retryPublication) {
					continue
				}
				if !d.loaded {
					entry, err := c.repo.load(key)
					if err != nil {
						d.retryPublication = now.Add(time.Second)
						continue
					}
					d.cache = entry
					d.loaded = true
				}
				if !d.bound {
					state, source := "queued", "measured"
					if d.cache.Best.replies() > 0 && now.Before(d.cache.ValidUntil) {
						state, source = "cached", "cache"
					}
					if !save(d, snapshot{Location: c.repo.location(d.target.IP)}, state, source, now) {
						continue
					}
					d.bound = true
					if source == "cache" {
						hits++
					}
				}
				if !d.retryPublication.IsZero() {
					save(d, d.cache.Last, d.cache.Last.Status, "measured", now)
					continue
				}
				needsCoverage := !d.cache.Best.Reached || d.cache.Best.coverage() < 1
				repair := important[d.key] && needsCoverage && d.cache.Last.Attempt != "" && !now.Before(d.cache.QualityNext) && !now.Before(coverageUnavailableUntil)
				fastDue := !now.Before(d.cache.RetryAt) && (!d.cache.Best.Reached || !now.Before(d.cache.FreshUntil))
				if !repair && !fastDue {
					continue
				}
				d.plan = probePlan{}
				if repair && len(coverageSlots) == 0 {
					d.plan = probePlan{Quality: true, Method: qualityMethods(d.target)[d.cache.QualityIndex%3]}
				} else if !fastDue {
					continue
				}

				if now.Sub(d.first) > 10*time.Second && weight == 0 {
					continue
				}
				queue = append(queue, d)
			}
			sort.Slice(queue, func(i, j int) bool {
				a, b := queue[i], queue[j]
				wa, wb := a.weight(now), b.weight(now)
				if a.plan.Quality != b.plan.Quality {
					return !a.plan.Quality
				}
				if important[a.key] != important[b.key] {
					return important[a.key]
				}
				if a.cache.Best.replies() == 0 && b.cache.Best.replies() > 0 {
					return true
				}
				if b.cache.Best.replies() == 0 && a.cache.Best.replies() > 0 {
					return false
				}
				if wa != wb {
					return wa > wb
				}
				if !a.first.Equal(b.first) {
					return a.first.Before(b.first)
				}
				return a.key < b.key
			})
			// Reclaim only a background repair; foreground processes get their short deadline.
			if len(queue) > 0 && running >= c.config.Workers && background > 0 {
				for _, d := range demands {
					if d.running && d.slow && (!queue[0].plan.Quality || d.weight(now) < queue[0].weight(now)) {
						d.cancel()
						break
					}
				}
			}
			for len(queue) > 0 && len(slots) < c.config.Workers {
				index := 0
				if starts%4 == 3 {
					for i, d := range queue {
						if d.plan.Quality == queue[0].plan.Quality && d.first.Before(queue[index].first) {
							index = i
						}
					}
				}
				d := queue[index]
				queue = append(queue[:index], queue[index+1:]...)
				slow := d.plan.Quality
				if slow {
					if len(coverageSlots) > 0 {
						continue
					}
					coverageSlots <- struct{}{}
					d.cache.QualityNext = now.Add(10 * time.Minute)
					background++
				}
				generation++
				d.generation = generation
				d.running = true
				slots <- struct{}{}
				d.slow = slow
				running++
				starts++
				jobctx, cancel := context.WithCancel(ctx)
				d.cancel = cancel
				state := "probing"
				if d.cache.Best.replies() > 0 && now.Before(d.cache.ValidUntil) {
					state = "refreshing"
				}
				save(d, snapshot{}, state, "measured", now)
				go func(key string, g uint64, t target, plan probePlan) {
					if plan.Quality {
						defer func() { <-coverageSlots }()
					}
					defer func() { <-slots }()
					emit := func(s snapshot, terminal bool) {
						select {
						case updates <- progress{key, g, s, terminal}:
						case <-ctx.Done():
						}
					}
					s := c.probe.Run(jobctx, t, plan, func(s snapshot) { emit(s, false) })
					emit(s, true)
					cancel()
				}(d.key, d.generation, d.target, d.plan)
			}
			oldest := int64(0)
			for _, d := range queue {
				oldest = max(oldest, now.Sub(d.first).Milliseconds())
			}
			c.mu.Lock()
			lastErr := c.stats.LastError
			coverage := float64(0)
			if recentBytes > 0 {
				coverage = float64(coveredBytes) / float64(recentBytes)
			}
			denominator := float64(max(recentBytes, 1))
			c.stats = Stats{CoverageRunning: len(coverageSlots), ReachedByteCoverage: float64(reachedBytes) / denominator, LocatedByteCoverage: float64(locatedBytes) / denominator, HopCoverage: hopCoverage / denominator, RecentBytes: recentBytes, MeasuredByteCoverage: coverage, Pending: len(queue), Running: len(slots), Starts: starts, CacheHits: hits, Deferred: deferred, Failures: failures, OldestWaitMS: oldest, LastError: lastErr, Network: network, UpdatedAt: date(now)}
			c.mu.Unlock()
			if now.Sub(lastPrune) > time.Minute {
				if err := c.repo.prune(now); err != nil {
					log.Printf("route cache retention: %v", err)
				}
				lastPrune = now
			}
			if now.Sub(lastLog) > 10*time.Second {
				log.Printf("route discovery pending=%d running=%d starts=%d cache_hits=%d failures=%d oldest_wait_ms=%d", len(queue), running, starts, hits, failures, oldest)
				lastLog = now
			}
		}
	}
}
