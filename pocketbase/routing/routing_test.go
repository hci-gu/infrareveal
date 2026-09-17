package routing

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	_ "myapp/migrations"
)

func testApp(t *testing.T) *pocketbase.PocketBase {
	t.Helper()
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	return app
}
func testSession(t *testing.T, app core.App) string {
	t.Helper()
	c, _ := app.FindCollectionByNameOrId("sessions")
	r := core.NewRecord(c)
	r.Set("active", true)
	if err := app.Save(r); err != nil {
		t.Fatal(err)
	}
	return r.Id
}
func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true within 3s")
}

type scriptedProbe struct {
	starts chan target
	finish chan struct{}
}

func (p scriptedProbe) Run(ctx context.Context, t target, plan probePlan, publish func(snapshot)) snapshot {
	p.starts <- t
	now := time.Now().UTC()
	s := snapshot{Attempt: hash(t.binding() + date(now))[:24], Revision: 1, Method: t.method(), Started: now, Measured: now, Status: "probing", Hops: []Hop{{TTL: 1, Address: "1.1.1.1", State: "reply", Timings: []float64{1}}}}
	publish(s)
	select {
	case <-p.finish:
		s.Reached = true
		s.Hops = append(s.Hops, Hop{TTL: 2, Address: t.IP, State: "reply", Timings: []float64{2}})
		s.Status = "reached"
	case <-ctx.Done():
		s.Status = "cancelled"
	}
	s.Revision++
	s.Finished = time.Now().UTC()
	return s
}

func TestCoordinatorProgressiveCacheReuseAndReset(t *testing.T) {
	app := testApp(t)
	first := testSession(t, app)
	second := testSession(t, app)
	var session atomic.Value
	session.Store(first)
	p := scriptedProbe{starts: make(chan target, 20), finish: make(chan struct{})}
	config := ConfigFromEnv()
	config.Interval = 10 * time.Millisecond
	config.Workers = 1
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), repo: repository{app: app}, config: config, probe: p, session: func() string { return session.Load().(string) }, network: func() (string, error) { return "test-network", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	go c.run(ctx)
	t.Cleanup(func() { cancel(); <-c.done })
	eventually(t, func() bool { return c.Status().Network == "test-network" })
	observe := func(id, sessionID string) {
		c.Observe(Flow{ID: id, Session: sessionID, IP: "9.9.9.9", Port: 443, Protocol: "tcp", At: time.Now(), Bytes: 2_000_000})
	}
	observe("flow-1", first)
	observe("flow-2", first)
	eventually(t, func() bool {
		records, _ := app.FindAllRecords("routes")
		for _, r := range records {
			if r.GetInt("responding_hops") == 1 && r.GetString("completed_at") == "" {
				return true
			}
		}
		return false
	})
	if len(p.starts) != 1 {
		t.Fatalf("same destination spawned %d probes", len(p.starts))
	}
	close(p.finish)
	eventually(t, func() bool {
		records, _ := app.FindAllRecords("routes")
		for _, r := range records {
			if r.GetBool("destination_reached") {
				return true
			}
		}
		return false
	})
	session.Store(second)
	observe("flow-3", second)
	eventually(t, func() bool {
		records, _ := app.FindAllRecords("routes")
		for _, r := range records {
			if r.GetString("session") == second && r.GetString("provenance") == "cache" && r.GetBool("complete") {
				return true
			}
		}
		return false
	})
	if len(p.starts) != 1 {
		t.Fatal("cache hit launched another probe")
	}
	c.Reset()
	observe("flow-4", second)
	eventually(t, func() bool { return c.Status().CacheHits >= 2 })
	if len(p.starts) != 1 {
		t.Fatal("persistent cache was lost when coordinator reset")
	}
}

func TestRepositoryFailedRefreshKeepsAgeAndEvidence(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	now := time.Now().UTC()
	target := target{"9.9.9.9", "tcp", 443}
	best := snapshot{Attempt: "good", Revision: 1, Started: now, Measured: now, Finished: now, Method: "tcp:443", Reached: true, Hops: []Hop{{TTL: 1, Address: "1.1.1.1", State: "reply"}, {TTL: 2, Address: "9.9.9.9", State: "reply"}}}
	entry := cacheEntry{Best: best, Last: best, FreshUntil: now.Add(time.Minute), ValidUntil: now.Add(time.Hour)}
	entry, err := repo.publish("key", "network", session, target, entry, best, "reached", "measured", now)
	if err != nil {
		t.Fatal(err)
	}
	failed := snapshot{Attempt: "failure", Revision: 1, Error: "timeout", Measured: now.Add(time.Second), Finished: now.Add(time.Second)}
	entry.Last = failed
	_, err = repo.publish("key", "network", session, target, entry, failed, "cached", "measured", now.Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	restored, err := repo.load("key")
	if err != nil {
		t.Fatal(err)
	}
	if !restored.Best.Measured.Equal(now) || restored.Best.ObservationID == "" {
		t.Fatalf("cache lost provenance: %#v", restored)
	}
	records, _ := app.FindAllRecords("routes")
	if len(records) != 1 {
		t.Fatal(len(records))
	}
	for _, r := range records {
		if !r.GetBool("complete") {
			t.Fatal("failed refresh erased useful route")
		}
	}
}

func TestProbePublishesUnterminatedHopBeforeExit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traceroute")
	script := "#!/bin/sh\nprintf 'traceroute to 9.9.9.9\\n 1  1.1.1.1  1.0 ms'\nsleep 0.4\nprintf '\\n 2  9.9.9.9  2.0 ms'\n"
	if err := os.WriteFile(path, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	began := time.Now()
	early := false
	s := (commandProbe{deadline: time.Second, executable: path}).Run(context.Background(), target{"9.9.9.9", "tcp", 443}, probePlan{}, func(s snapshot) {
		if len(s.Hops) == 1 && time.Since(began) < 350*time.Millisecond {
			early = true
		}
	})
	if !early || !s.Reached || len(s.Hops) != 2 {
		t.Fatalf("no progressive pipe output or terminal reply: early=%v result=%#v", early, s)
	}
}
func TestProbeRetainsPartialRepliesOnDeadline(t *testing.T) {
	path := filepath.Join(t.TempDir(), "traceroute")
	_ = os.WriteFile(path, []byte("#!/bin/sh\nprintf '\\n 1  2001:4860:4860::8888  2.0 ms\\n 2  *'\nexec sleep 2\n"), 0700)
	s := (commandProbe{deadline: 200 * time.Millisecond, executable: path}).Run(context.Background(), target{"2001:4860:4860::8844", "udp", 443}, probePlan{}, func(snapshot) {})
	if s.replies() != 1 || s.Reached || s.Error != context.DeadlineExceeded.Error() || s.Hops[1].State != "no_reply" || s.Hops[2].State != "unknown" {
		t.Fatalf("lost partial evidence: %#v", s)
	}
}
func TestParserRejectsIncompleteTimingAndPreservesUnreachable(t *testing.T) {
	if got := parseHops([]byte("\n 1  1.1.1.1  1.")); len(got) != 0 {
		t.Fatal(got)
	}
	got := parseHops([]byte("\n 1  1.1.1.1  1.0 ms !X"))
	if len(got) != 1 || got[0].State != "unreachable" {
		t.Fatal(got)
	}
}

func TestNetworkInvalidatesBindingsAbsentFromDemandMemory(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	if err := repo.invalidateSession(session, "old", time.Now()); err != nil {
		t.Fatal(err)
	}
	events, _ := app.FindAllRecords("route_evidence_updates")
	routes, _ := app.FindAllRecords("routes")
	if len(events) != 1 || len(routes) != 0 || events[0].GetString("kind") != "network_invalidated" {
		t.Fatal("invalidation must be an epoch, not fake routes")
	}
}

func TestPendingStateCreatesNoRoute(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	if _, err := repo.publish("key", "network", session, target{"9.9.9.9", "tcp", 443}, cacheEntry{}, snapshot{}, "queued", "measured", time.Now()); err != nil {
		t.Fatal(err)
	}
	records, _ := app.FindAllRecords("routes")
	if len(records) != 0 {
		t.Fatal("pending state created a route")
	}
}

func TestRetentionUsesExactTimeAcrossDateFormats(t *testing.T) {
	app := testApp(t)
	repo := repository{app: app}
	now := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	for _, age := range []time.Duration{23 * time.Hour, 25 * time.Hour} {
		key := age.String()
		if err := saveCache(app, key, cacheEntry{}, now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	if err := repo.prune(now); err != nil {
		t.Fatal(err)
	}
	records, _ := app.FindAllRecords("route_cache")
	if len(records) != 1 || records[0].GetString("cache_key") != (23*time.Hour).String() {
		t.Fatalf("wrong retention boundary: %v", records)
	}
}

func TestCoordinatorPromotesQualifiedTraffic(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	p := scriptedProbe{starts: make(chan target, 100), finish: make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	for i := 1; i <= 79; i++ {
		c.Observe(Flow{ID: fmt.Sprint(i), IP: fmt.Sprintf("8.0.0.%d", i), Session: session, Protocol: "tcp", Port: 443, Bytes: 100, At: time.Now()})
	}
	c.Observe(Flow{ID: "busy", IP: "9.9.9.9", Session: session, Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	select {
	case got := <-p.starts:
		if got.IP != "9.9.9.9" {
			t.Fatal(got)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("qualified destination did not start")
	}
	if len(p.starts) != 0 {
		t.Fatal("low activity triggered probes")
	}
}

type drainingProbe struct {
	active, peak atomic.Int32
	starts       chan struct{}
}

func (p *drainingProbe) Run(ctx context.Context, target target, plan probePlan, publish func(snapshot)) snapshot {
	n := p.active.Add(1)
	for old := p.peak.Load(); n > old; old = p.peak.Load() {
		if p.peak.CompareAndSwap(old, n) {
			break
		}
	}
	p.starts <- struct{}{}
	<-ctx.Done()
	time.Sleep(150 * time.Millisecond) // subprocess pipe-drain after cancellation
	p.active.Add(-1)
	return snapshot{Status: "cancelled"}
}
func TestWorkerBudgetSurvivesResetWhileCancelledProcessesDrain(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	p := &drainingProbe{starts: make(chan struct{}, 8)}
	config := ConfigFromEnv()
	config.Workers, config.Interval = 2, 10*time.Millisecond
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), repo: repository{app: app}, config: config, probe: p, session: func() string { return session }, network: func() (string, error) { return "network", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	go c.run(ctx)
	t.Cleanup(func() { cancel(); <-c.done; eventually(t, func() bool { return p.active.Load() == 0 }) })
	eventually(t, func() bool { return c.Status().Network == "network" })
	observe := func(ip string) {
		c.Observe(Flow{ID: ip, Session: session, IP: ip, Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	}
	observe("203.0.113.1")
	observe("203.0.113.2")
	eventually(t, func() bool { return len(p.starts) == 1 })
	c.Reset()
	observe("203.0.113.3")
	observe("203.0.113.4")
	eventually(t, func() bool { return len(p.starts) == 2 })
	if p.peak.Load() > 1 {
		t.Fatalf("cancelled workers escaped the shared budget: %d", p.peak.Load())
	}
}
