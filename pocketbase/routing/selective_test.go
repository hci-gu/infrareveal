package routing

import (
	"context"
	"fmt"
	"github.com/pocketbase/pocketbase/core"
	"sync"
	"testing"
	"time"
)

func startTestCoordinator(t *testing.T, app core.App, session string, p prober) *Coordinator {
	t.Helper()
	config := ConfigFromEnv()
	config.Interval = 10 * time.Millisecond
	c := &Coordinator{intake: map[string]Flow{}, reset: make(chan chan struct{}), done: make(chan struct{}), repo: repository{app: app}, config: config, probe: p, session: func() string { return session }, network: func() (string, error) { return "network", nil }}
	ctx, cancel := context.WithCancel(context.Background())
	go c.run(ctx)
	t.Cleanup(func() { cancel(); <-c.done })
	eventually(t, func() bool { return c.Status().Network == "network" })
	return c
}
func useful(at time.Time, attempt string) snapshot {
	return snapshot{Attempt: attempt, Revision: 1, Method: "tcp:443", Measured: at, Started: at, Finished: at, Status: "reached", Reached: true, ProbedTTL: 13, Hops: []Hop{{TTL: 1, Address: "192.168.1.1", State: "reply"}, {TTL: 2, Address: "1.1.1.1", State: "reply"}, {TTL: 8, Address: "8.8.4.4", State: "reply"}, {TTL: 13, Address: "9.9.9.9", State: "reply"}}}
}
func TestEvidenceClassificationAndFingerprint(t *testing.T) {
	tgt := target{"9.9.9.9", "tcp", 443}
	s := useful(time.Now(), "a")
	if got := classifyRouteEvidence(s, tgt, nil).Class; got != "useful_path" {
		t.Fatal(got)
	}
	s.Hops = s.Hops[3:]
	if got := classifyRouteEvidence(s, tgt, nil).Class; got != "endpoint_only" {
		t.Fatal(got)
	}
	s.Reached = false
	s.Hops = nil
	s.Status = "unavailable"
	if classifyRouteEvidence(s, tgt, nil).Class != "no_path" {
		t.Fatal("silent path counted useful")
	}
	s = useful(time.Now(), "a")
	f := pathFingerprint(s, tgt, "net")
	s.Attempt = "b"
	s.Measured = time.Now().Add(time.Hour)
	s.Hops[0].Timings = []float64{500}
	s.Hops = append(s.Hops, Hop{TTL: 14, Missing: true, State: "no_reply"})
	if f != pathFingerprint(s, tgt, "net") {
		t.Fatal("noise changed material fingerprint")
	}
	s.Hops[1].Address = "8.8.8.8"
	if f == pathFingerprint(s, tgt, "net") {
		t.Fatal("real topology change lost")
	}
}

func TestEvidencePolicyTable(t *testing.T) {
	tgt := target{"9.9.9.9", "tcp", 443}
	for _, tc := range []struct {
		name string
		s    snapshot
		want string
	}{
		{"silent", snapshot{Status: "unavailable"}, "no_path"},
		{"local", snapshot{Hops: []Hop{{TTL: 1, Address: "192.168.1.1"}}}, "access_only"},
		{"endpoint", snapshot{Reached: true, Hops: []Hop{{TTL: 13, Address: tgt.IP}}}, "endpoint_only"},
		{"reached after silent middle", snapshot{Reached: true, Hops: []Hop{{TTL: 1, Address: "192.168.1.1"}, {TTL: 13, Address: tgt.IP}}}, "access_only"},
		{"unlocated public", snapshot{Hops: []Hop{{TTL: 5, Address: "1.1.1.1"}}}, "useful_path"},
		{"cancelled", snapshot{Status: "cancelled"}, "indeterminate"},
		{"local failure", snapshot{Status: "failed"}, "indeterminate"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifyRouteEvidence(tc.s, tgt, nil); got.Class != tc.want {
				t.Fatal(got)
			}
		})
	}
}

// Replays the shape captured in the Pi's 17 September "testing" session:
// two shared access hops, a long silent span, then a responding TCP endpoint.
func TestReachedAccessPrefixDoesNotEndMethodComparison(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	config := ConfigFromEnv()
	tgt := target{"162.159.130.234", "tcp", 443}
	now := time.Now()
	a, err := repo.reserve(session, "network", tgt, config, false, now)
	if err != nil || a.Reason != "" {
		t.Fatalf("first admission: %+v %v", a, err)
	}
	s := snapshot{Attempt: a.Attempt, Method: "tcp:443", Started: now, Measured: now, Finished: now, Status: "reached", Reached: true, ProbedTTL: 11,
		Hops: []Hop{{TTL: 1, Address: "192.168.10.1"}, {TTL: 2, Address: "130.241.190.9"}, {TTL: 3, EndTTL: 10, Missing: true, State: "no_reply"}, {TTL: 11, Address: tgt.IP}}}
	if _, err = repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{}, s, s.Status, "measured", now); err != nil {
		t.Fatal(err)
	}
	if rows, err := app.FindAllRecords("routes"); err != nil || len(rows) != 0 {
		t.Fatalf("access plus endpoint created useful routes: %d %v", len(rows), err)
	}
	second, err := repo.reserve(session, "network", tgt, config, false, now.Add(time.Second))
	if err != nil || second.Reason != "" || second.Method != "icmp-paris" {
		t.Fatalf("sparse endpoint stopped the alternate: %+v %v", second, err)
	}
	access := []accessPosition{{1, []string{"192.168.10.1"}}, {2, []string{"130.241.190.9"}}}
	if got := classifyRouteEvidence(s, tgt, access); got.Class != "access_only" {
		t.Fatalf("endpoint promoted known access to useful: %+v", got)
	}
}

type idleComparisonProbe struct{ methods chan string }

func (p idleComparisonProbe) Run(_ context.Context, _ target, plan probePlan, _ func(snapshot)) snapshot {
	p.methods <- plan.Method
	now := time.Now()
	return snapshot{Method: plan.Method, Started: now, Measured: now, Finished: now, Status: "failed", Error: "context deadline exceeded"}
}
func TestAdmittedComparisonContinuesAfterActivityExpires(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	tgt := target{"151.101.3.6", "udp", 443}
	repo := repository{app: app}
	// Persist a first attempt as if the process restarted after its 45-second
	// timeout. The remaining method must not require another browsing burst.
	now := time.Now()
	a, err := repo.reserve(session, "network", tgt, ConfigFromEnv(), false, now.Add(-time.Minute))
	if err != nil || a.Reason != "" {
		t.Fatalf("first admission: %+v %v", a, err)
	}
	s := snapshot{Attempt: a.Attempt, Method: a.Method, Finished: now, Measured: now, Status: "failed", Error: "context deadline exceeded"}
	if _, err = repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{}, s, s.Status, "measured", now); err != nil {
		t.Fatal(err)
	}
	p := idleComparisonProbe{make(chan string, 3)}
	c := startTestCoordinator(t, app, session, p)
	c.Observe(Flow{ID: "idle-flow", Session: session, IP: tgt.IP, Protocol: tgt.Protocol, Port: tgt.Port, At: now, Bytes: 100, Baseline: true})
	select {
	case method := <-p.methods:
		if method != "icmp-paris" {
			t.Fatal(method)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted alternate required fresh qualifying activity")
	}
	eventually(t, func() bool { return c.Status().Running == 0 })
	select {
	case method := <-p.methods:
		t.Fatalf("comparison exceeded two methods: %s", method)
	case <-time.After(300 * time.Millisecond):
	}
}

func TestConcurrentAdmissionCannotOverspendSessionTargets(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	config := ConfigFromEnv()
	config.MaxTargets = 5
	var wg sync.WaitGroup
	results := make(chan admission, 20)
	errs := make(chan error, 20)
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			a, err := repo.reserve(session, fmt.Sprint("n", i), target{"9.9.9.9", "tcp", 443}, config, false, time.Now())
			results <- a
			errs <- err
		}(i)
	}
	wg.Wait()
	close(results)
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	admitted := 0
	ports := map[int]bool{}
	for a := range results {
		if a.Reason == "" {
			admitted++
			if ports[a.SourcePort] {
				t.Fatal("reused live probe identity")
			}
			ports[a.SourcePort] = true
		}
	}
	if admitted != 5 {
		t.Fatalf("admitted %d targets, expected five", admitted)
	}
}

func TestDiagnosticReportsCapturedButUndecodedResponders(t *testing.T) {
	headers := "12:00:00 IP 10.0.0.1 > 10.0.0.2: ICMP time exceeded in-transit\n12:00:01 IP 9.9.9.9.443 > 10.0.0.2.45000: Flags [R.]"
	result := diagnosticReplyAccounting(headers, []Hop{{TTL: 2, Address: "9.9.9.9"}})
	if result["candidate_match_failures"] != 1 || fmt.Sprint(result["captured_not_decoded"]) != "[10.0.0.1]" {
		t.Fatal(result)
	}
}
func TestAccessConsensusNeedsThreeDistinctDestinations(t *testing.T) {
	a := accessEvidence{}
	s := useful(time.Now(), "a")
	s.Reached = false
	s.Hops = s.Hops[:2]
	for i := 0; i < 3; i++ {
		a = learnAccess(a, s, target{fmt.Sprintf("9.9.9.%d", i+1), "tcp", 443})
		if i < 2 && len(establishedAccess(a)) != 0 {
			t.Fatal("premature access consensus")
		}
	}
	if len(establishedAccess(a)) != 2 || classifyRouteEvidence(s, target{"9.9.9.9", "tcp", 443}, establishedAccess(a)).Class != "access_only" {
		t.Fatal(a)
	}
	s.Hops = append(s.Hops, Hop{TTL: 8, Address: "8.8.8.8"})
	if classifyRouteEvidence(s, target{"9.9.9.9", "tcp", 443}, establishedAccess(a)).Class != "useful_path" {
		t.Fatal("lost public interface beyond access")
	}
}
func Test5200PublicationsDoNotBecomeRoutes(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	tgt := target{"9.9.9.9", "tcp", 443}
	at := time.Now()
	for i := 0; i < 5200; i++ {
		s := snapshot{Attempt: "silent", Revision: i, Status: "probing", Method: "tcp:443", Measured: at, Hops: []Hop{{TTL: 1, Missing: true, State: "no_reply"}}}
		if _, e := repo.publish(tgt.key("n"), "n", session, tgt, cacheEntry{}, s, "probing", "measured", at); e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"routes", "route_observations", "route_outcomes", "route_budget_state"} {
		rows, _ := app.FindAllRecords(name)
		if len(rows) != 0 {
			t.Fatalf("relocated progress explosion into %s: %d", name, len(rows))
		}
	}
	s := useful(at, "good")
	entry, e := repo.publish(tgt.key("n"), "n", session, tgt, cacheEntry{}, s, "reached", "measured", at)
	if e != nil {
		t.Fatal(e)
	}
	for i := 0; i < 100; i++ {
		s.Attempt = fmt.Sprint(i)
		s.Measured = at.Add(time.Duration(i) * time.Second)
		s.Finished = s.Measured
		_, e = repo.publish(tgt.key("n"), "n", session, tgt, entry, s, "reached", "measured", s.Measured)
		if e != nil {
			t.Fatal(e)
		}
	}
	for _, name := range []string{"routes", "route_observations", "route_outcomes"} {
		rows, _ := app.FindAllRecords(name)
		if len(rows) != 1 {
			t.Fatalf("unchanged path created %d %s", len(rows), name)
		}
	}
}
func TestFiveSilentComparisonsPauseNetworkAndSurviveRestart(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	c := ConfigFromEnv()
	now := time.Now()
	for i := 0; i < 5; i++ {
		tgt := target{fmt.Sprintf("8.8.8.%d", i+1), "tcp", 443}
		for j := 0; j < 2; j++ {
			now = now.Add(time.Second)
			a, e := repo.reserve(session, "network", tgt, c, false, now)
			if e != nil || a.Reason != "" {
				t.Fatalf("admission: %+v %v", a, e)
			}
			s := snapshot{Attempt: a.Attempt, Method: a.Method, Measured: now, Finished: now, Status: "unavailable"}
			if _, e = repo.publish(tgt.key("network"), "network", session, tgt, cacheEntry{}, s, s.Status, "measured", now); e != nil {
				t.Fatal(e)
			}
		}
	}
	second := testSession(t, app)
	freshRepo := repository{app: app}
	a, e := freshRepo.reserve(second, "network", target{"9.9.9.9", "tcp", 443}, c, false, now.Add(time.Second))
	if e != nil || a.Reason != "visibility_paused" {
		t.Fatalf("lost persistent suppression: %+v %v", a, e)
	}
	rows, _ := app.FindAllRecords("routes")
	outcomes, _ := app.FindAllRecords("route_outcomes")
	if len(rows) != 0 || len(outcomes) != 5 {
		t.Fatalf("silent work stored %d routes / %d outcomes", len(rows), len(outcomes))
	}
}
func TestPersistentAdmissionBudgets(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	c := ConfigFromEnv()
	now := time.Now()
	admitted := 0
	for i := 0; i < 1000; i++ {
		a, e := repo.reserve(session, "network", target{fmt.Sprintf("8.1.%d.%d", i/250, i%250+1), "tcp", 443}, c, false, now.Add(time.Duration(i)*time.Second))
		if e != nil {
			t.Fatal(e)
		}
		if a.Reason == "" {
			admitted++
		}
	}
	if admitted != 20 {
		t.Fatalf("admitted %d", admitted)
	}
	fresh := repository{app: app}
	_, b, e := loadSessionBudget(app, session)
	if e != nil || b.Attempts != 20 {
		t.Fatal(b, e)
	}
	a, e := fresh.reserve(session, "network", target{"9.9.9.9", "tcp", 443}, c, false, now.Add(time.Hour))
	if e != nil || a.Reason != "target_budget" {
		t.Fatal(a, e)
	}
}
func TestSnapshotAndByteLimits(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	c := ConfigFromEnv()
	c.MaxSnapshots = 2
	repo := repository{app: app, config: c}
	tgt := target{"9.9.9.9", "tcp", 443}
	now := time.Now()
	for i := 0; i < 10; i++ {
		s := useful(now, fmt.Sprint(i))
		s.Hops[1].Address = fmt.Sprintf("8.8.8.%d", i+1)
		if _, e := repo.publish(tgt.key("n"), "n", session, tgt, cacheEntry{}, s, "reached", "measured", now); e != nil {
			t.Fatal(e)
		}
	}
	rows, _ := app.FindAllRecords("routes")
	if len(rows) != 2 {
		t.Fatal(len(rows))
	}
}

func TestTerminalRetriesAndNetworkRestartAreIdempotent(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	now := time.Now()
	tgt := target{"9.9.9.9", "tcp", 443}
	if err := repo.activateNetwork(session, "old", now); err != nil {
		t.Fatal(err)
	}
	s := useful(now, "one")
	for _, id := range []string{"one", "two", "one", "two"} {
		s.Attempt = id
		if _, err := repo.publish(tgt.key("old"), "old", session, tgt, cacheEntry{}, s, "reached", "measured", now); err != nil {
			t.Fatal(err)
		}
	}
	_, b, _ := loadSessionBudget(app, session)
	if b.Duplicates != 1 || len(b.Completed) != 2 {
		t.Fatalf("duplicate terminal callbacks changed counters: %+v", b)
	}
	fresh := repository{app: app}
	if err := fresh.activateNetwork(session, "new", now.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := fresh.activateNetwork(session, "new", now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	events, _ := app.FindAllRecords("route_evidence_updates")
	if len(events) != 1 || events[0].GetString("network_context") != "old" {
		t.Fatal("restart lost/coalesced wrong source epoch", events)
	}
}

func TestByteLimitAndTerminalStateSurviveRejectedGeometry(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	c := ConfigFromEnv()
	c.MaxBytes = 9000
	repo := repository{app: app, config: c}
	now := time.Now()
	tgt := target{"9.9.9.9", "tcp", 443}
	s := useful(now, "large")
	if _, err := repo.publish(tgt.key("n"), "n", session, tgt, cacheEntry{}, s, "reached", "measured", now); err != nil {
		t.Fatal(err)
	}
	rows, _ := app.FindAllRecords("routes")
	outcomes, _ := app.FindAllRecords("route_outcomes")
	_, b, _ := loadSessionBudget(app, session)
	if len(rows) != 0 || len(outcomes) != 1 || !b.Completed[s.Attempt] || b.Bytes > c.MaxBytes {
		t.Fatalf("budget lost terminal outcome or exceeded limit: rows=%d outcomes=%d %+v", len(rows), len(outcomes), b)
	}
}

func TestExpiredVisibilityPauseAllowsOnlyOneFailedTrial(t *testing.T) {
	app := testApp(t)
	session := testSession(t, app)
	repo := repository{app: app}
	now := time.Now()
	tgt := target{"9.9.9.9", "tcp", 443}
	n := networkBudget{PausedUntil: now.Add(-time.Second), NoGain: []string{"1", "2", "3", "4", "5"}}
	rec, _ := loadState(app, networkKey("n", tgt), &networkBudget{})
	if err := saveState(app, rec, n); err != nil {
		t.Fatal(err)
	}
	a, err := repo.reserve(session, "n", tgt, ConfigFromEnv(), false, now)
	if err != nil || a.Reason != "" {
		t.Fatal(a, err)
	}
	s := snapshot{Attempt: a.Attempt, Method: a.Method, Status: "unavailable", Measured: now, Finished: now}
	if _, err := repo.publish(tgt.key("n"), "n", session, tgt, cacheEntry{}, s, s.Status, "measured", now); err != nil {
		t.Fatal(err)
	}
	next, err := repo.reserve(session, "n", target{"8.8.8.8", "tcp", 443}, ConfigFromEnv(), false, now.Add(time.Second))
	if err != nil || next.Reason != "visibility_paused" {
		t.Fatal(next, err)
	}
}
