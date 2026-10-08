package routing

import (
	"context"
	"encoding/json"
	"errors"
	"myapp/testsupport"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

type terminalProbe struct {
	starts atomic.Int32
}

func (p *terminalProbe) Run(_ context.Context, _ target, _ probePlan, _ func(snapshot)) snapshot {
	p.starts.Add(1)
	now := time.Now()
	return snapshot{Started: now, Measured: now, Finished: now, Status: "partial", Hops: []Hop{{TTL: 5, Address: "1.1.1.1", State: "reply"}}}
}

func TestPublicationRollbackRetriesWithoutAnotherAdmission(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	var failures atomic.Int32
	// Fail the final session-budget save, after geometry and cache construction.
	// The real PocketBase transaction must roll back all of them together.
	app.OnRecordUpdate("route_budget_state").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("key") == "session:"+session {
			var b sessionBudget
			data, _ := json.Marshal(e.Record.Get("value"))
			if json.Unmarshal(data, &b) == nil && len(b.Completed) > 0 && failures.CompareAndSwap(0, 1) {
				return errors.New("injected publication failure")
			}
		}
		return e.Next()
	})
	p := &terminalProbe{}
	c := startTestCoordinator(t, app, session, p)
	c.Observe(Flow{ID: "one", Session: session, IP: "9.9.9.9", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	eventually(t, func() bool { return strings.Contains(c.Status().LastError, "injected publication failure") })
	for _, name := range []string{"routes", "route_observations", "route_cache", "route_outcomes"} {
		rows, err := app.FindAllRecords(name)
		if err != nil || len(rows) != 0 {
			t.Fatalf("uncommitted %s escaped rollback: %d %v", name, len(rows), err)
		}
	}
	if c.Status().MeasuredByteCoverage != 0 {
		t.Fatal("uncommitted evidence entered live cache coverage")
	}
	eventually(t, func() bool { return c.Status().UsefulPaths == 1 && c.Status().Running == 0 })
	_, b, err := loadSessionBudget(app, session)
	if err != nil || b.Attempts != 1 || len(b.Completed) != 1 || b.Snapshots != 1 || b.Duplicates != 0 || p.starts.Load() != 1 {
		t.Fatalf("retry changed admission/accounting: %+v starts=%d err=%v", b, p.starts.Load(), err)
	}
	for _, name := range []string{"routes", "route_observations", "route_cache", "route_outcomes"} {
		rows, err := app.FindAllRecords(name)
		if err != nil || len(rows) != 1 {
			t.Fatalf("retry created %d %s: %v", len(rows), name, err)
		}
	}
}

type heldResultProbe struct {
	starts    chan struct{}
	cancelled chan struct{}
	drain     chan struct{}
}

func (p heldResultProbe) Run(ctx context.Context, _ target, _ probePlan, _ func(snapshot)) snapshot {
	p.starts <- struct{}{}
	<-ctx.Done()
	close(p.cancelled)
	<-p.drain
	now := time.Now()
	return snapshot{Started: now, Measured: now, Finished: now, Status: "partial", Hops: []Hop{{TTL: 5, Address: "1.1.1.1"}}}
}

func TestResetFencesAcceptedIntakeAndLateUsefulResult(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := heldResultProbe{make(chan struct{}, 1), make(chan struct{}), make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	c.Observe(Flow{ID: "running", Session: session, IP: "9.9.9.9", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	select {
	case <-p.starts:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	// This accepted observation either sits in intake or demand memory. Both
	// must be gone when reset acknowledges, even while the first worker drains.
	c.Observe(Flow{ID: "queued", Session: session, IP: "8.8.8.8", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	c.Reset()
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("reset did not cancel probe")
	}
	close(p.drain)
	eventually(t, func() bool { return c.Status().Running == 0 && len(c.Status().Targets) == 0 })
	rows, err := app.FindAllRecords("routes")
	if err != nil || len(rows) != 0 {
		t.Fatalf("late result committed after reset: %d %v", len(rows), err)
	}
	_, b, err := loadSessionBudget(app, session)
	if err != nil || b.Attempts != 1 {
		t.Fatalf("reset lost spending or ran old intake: %+v %v", b, err)
	}
	select {
	case <-p.starts:
		t.Fatal("pre-reset intake launched after acknowledgement")
	default:
	}
}

func TestCloseWaitsForDrainAndCanBeRetried(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := heldResultProbe{make(chan struct{}, 1), make(chan struct{}), make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	c.Observe(Flow{ID: "running", Session: session, IP: "9.9.9.9", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	select {
	case <-p.starts:
	case <-time.After(time.Second):
		t.Fatal("probe did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close did not wait for drain: %v", err)
	}
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("close did not cancel work")
	}
	if err := c.ExtendBudget(); err == nil {
		t.Fatal("closed coordinator accepted a mutation")
	}
	close(p.drain)
	ctx, finish := context.WithTimeout(context.Background(), time.Second)
	defer finish()
	if err := c.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(ctx); err != nil {
		t.Fatal("close was not idempotent", err)
	}
	c.Reset() // A reset after shutdown must also return.
}

func TestResetContextTimeoutDoesNotAcknowledgeActivePublication(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	entered, release := make(chan struct{}), make(chan struct{})
	app.OnRecordCreate("route_cache").BindFunc(func(e *core.RecordEvent) error {
		close(entered)
		<-release
		return e.Next()
	})
	c := startTestCoordinator(t, app, session, &terminalProbe{})
	c.Observe(Flow{ID: "running", Session: session, IP: "9.9.9.9", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	select {
	case <-entered:
	case <-time.After(3 * time.Second):
		close(release)
		t.Fatal("publication did not begin")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := c.ResetContext(ctx)
	cancel()
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("reset acknowledged a still-active write: %v", err)
	}
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := c.ResetContext(ctx); err != nil {
		t.Fatal("reset could not be retried after publication completed", err)
	}
	rows, err := app.FindAllRecords("routes")
	if err != nil || len(rows) != 1 {
		t.Fatalf("timed-out reset damaged the committed result: %d %v", len(rows), err)
	}
}

func TestManualControlsUseObservedFlowAndSeparateBudget(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	flow := testsupport.Save(t, app, "flows", map[string]any{"session": session, "flow_key": "manual", "client_ip": "10.0.0.2", "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "start": time.Now()})
	p := idleComparisonProbe{make(chan string, 2)}
	c := startTestCoordinator(t, app, session, p)
	if err := c.Measure(context.Background(), flow.Id); err != nil {
		t.Fatal(err)
	}
	select {
	case method := <-p.methods:
		if method != "tcp" {
			t.Fatal(method)
		}
	case <-time.After(time.Second):
		t.Fatal("manual attempt did not start")
	}
	eventually(t, func() bool { return c.Status().Running == 0 && c.Status().ManualRemaining == 9 })
	_, b, err := loadSessionBudget(app, session)
	if err != nil || b.Attempts != 0 || b.Manual != 1 {
		t.Fatalf("manual work used automatic budget: %+v %v", b, err)
	}
	if err := c.Measure(context.Background(), "missing"); err == nil {
		t.Fatal("unobserved flow accepted")
	}
	for range 4 {
		if err := c.ExtendBudget(); err != nil {
			t.Fatal(err)
		}
	}
	if err := c.ExtendBudget(); err == nil {
		t.Fatal("unbounded session extension")
	}
	_, b, err = loadSessionBudget(app, session)
	if err != nil || b.ExtraTargets != 80 || b.ExtraAttempts != 160 {
		t.Fatalf("extension changed: %+v %v", b, err)
	}
	select {
	case method := <-p.methods:
		t.Fatal("manual request admitted automatic alternate", method)
	default:
	}
}

func TestManualAdmissionRetainsNetworkAndStorageLimits(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	config := ConfigFromEnv()
	config.ManualAttempts = 1
	store := evidenceStore{app: app, config: config}
	now := time.Now()
	binding := routeBinding{Session: session, Network: "network", Target: target{"9.9.9.9", "tcp", 443}}
	n := networkBudget{PausedUntil: now.Add(time.Hour)}
	r, _ := loadState(app, networkKey(binding.Network, binding.Target), &networkBudget{})
	if err := saveState(app, r, n); err != nil {
		t.Fatal(err)
	}
	a, err := store.reserve(binding, false, now)
	if err != nil || a.Reason != "visibility_paused" {
		t.Fatal(a, err)
	}
	a, err = store.reserve(binding, true, now)
	if err != nil || a.Reason != "" || a.Method != "tcp" {
		t.Fatal(a, err)
	}
	a, err = store.reserve(binding, true, now.Add(time.Second))
	if err != nil || a.Reason != "manual_budget" {
		t.Fatal(a, err)
	}
	store.config.HourlyAttempts = 1
	a, err = store.reserve(binding, true, now.Add(time.Second))
	if err != nil || a.Reason != "hourly_budget" {
		t.Fatal(a, err)
	}
	store.config.MaxSnapshots = 1
	a, err = store.reserve(binding, true, now.Add(time.Hour))
	if err != nil || a.Reason != "storage_budget" {
		t.Fatal(a, err)
	}
	store.config = config
	n.CapabilityUntil = now.Add(time.Hour)
	if err := saveState(app, r, n); err != nil {
		t.Fatal(err)
	}
	a, err = store.reserve(binding, true, now.Add(time.Second))
	if err != nil || a.Reason != "engine_unavailable" {
		t.Fatal(a, err)
	}
	binding.Network = "unknown"
	a, err = store.reserve(binding, true, now)
	if err != nil || a.Reason != "network_unavailable" {
		t.Fatal(a, err)
	}
}

func TestDisabledEngineRejectsManualMeasurement(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	config := ConfigFromEnv()
	config.Engine = "off"
	c := startTestCoordinator(t, app, session, idleComparisonProbe{make(chan string, 1)}, config)
	if err := c.Measure(context.Background(), "any"); err == nil || err.Error() != "route engine disabled" {
		t.Fatal(err)
	}
}
