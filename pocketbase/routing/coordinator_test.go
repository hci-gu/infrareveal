package routing

import (
	"context"
	"errors"
	"myapp/data"
	"myapp/testsupport"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

func eventually(t *testing.T, fn func() bool) {
	t.Helper()
	until := time.Now().Add(5 * time.Second)
	for time.Now().Before(until) {
		if fn() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("condition did not become true within 5s")
}
func startTestCoordinator(t *testing.T, app core.App, session string, p prober, configs ...Config) *Coordinator {
	t.Helper()
	cfg := defaultConfig()
	if len(configs) > 0 {
		cfg = configs[0]
	}
	return startCoordinatorWithNetwork(t, app, session, p, cfg, func() (string, error) { return "network", nil })
}
func startCoordinatorWithNetwork(t *testing.T, app core.App, session string, p prober, cfg Config, network func() (string, error)) *Coordinator {
	t.Helper()
	cfg.Interval = 10 * time.Millisecond
	c := &Coordinator{intake: map[string]Traffic{}, reset: make(chan chan struct{}), done: make(chan struct{}), stop: make(chan struct{}), requests: make(chan manualRequest, 10), repo: newEvidenceStore(app, nil, cfg), config: cfg, probe: p, enrich: func(_ context.Context, s snapshot) snapshot { return s }, session: func() string { return session }, network: network}
	ctx, cancel := context.WithCancel(context.Background())
	go c.run(ctx)
	t.Cleanup(func() { cancel(); <-c.done })
	eventually(t, func() bool { return c.NetworkEpoch() != "" && c.Status().Network == "network" })
	return c
}
func observe(c *Coordinator, session, ip string, bytes int64) {
	c.Observe(Traffic{Session: session, NetworkEpoch: c.NetworkEpoch(), IP: ip, Protocol: "tcp", Port: 443, Bytes: bytes, At: time.Now()})
}

type terminalProbe struct{ starts atomic.Int32 }

func (p *terminalProbe) Run(_ context.Context, _ target, _ probePlan) snapshot {
	p.starts.Add(1)
	now := time.Now()
	return useful(now, "")
}

type progressProbe struct{ started, finish chan struct{} }

func (p progressProbe) Run(ctx context.Context, _ target, _ probePlan) snapshot {
	now := time.Now()
	s := useful(now, "")
	s.Finished = time.Time{}
	close(p.started)
	select {
	case <-p.finish:
	case <-ctx.Done():
		s.Status = "cancelled"
	}
	s.Finished = time.Now()
	return s
}
func TestCoordinatorAcceptsAggregateDemandAfterCompletion(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := progressProbe{make(chan struct{}), make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	observe(c, session, "9.9.9.9", 2_000_000)
	select {
	case <-p.started:
	case <-time.After(time.Second):
		t.Fatal("aggregate did not qualify")
	}
	time.Sleep(30 * time.Millisecond)
	if len(routeRows(t, app)) != 0 {
		t.Fatal("progress became a path")
	}
	close(p.finish)
	eventually(t, func() bool { return len(routeRows(t, app)) == 1 })
	if _, err := app.FindCollectionByNameOrId("flows"); err == nil {
		t.Fatal("routing required old flows schema")
	}
	observe(c, session, "9.9.9.9", 2_000_000)
	eventually(t, func() bool { return c.Status().Running == 0 })
	if len(runRows(t, app)) != 1 {
		t.Fatal("useful binding probed repeatedly")
	}
}
func TestPublicationRetryDoesNotAdmitAnotherProbe(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	var failures atomic.Int32
	app.OnRecordUpdate("probe_runs").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("status") != "admitted" && failures.CompareAndSwap(0, 1) {
			return errors.New("injected publication failure")
		}
		return e.Next()
	})
	p := &terminalProbe{}
	c := startTestCoordinator(t, app, session, p)
	observe(c, session, "9.9.9.9", 2_000_000)
	eventually(t, func() bool { return strings.Contains(c.Status().LastError, "injected publication failure") })
	if len(routeRows(t, app)) != 0 {
		t.Fatal("rollback leaked route")
	}
	eventually(t, func() bool { return len(routeRows(t, app)) == 1 && c.Status().Running == 0 })
	if p.starts.Load() != 1 || len(runRows(t, app)) != 1 {
		t.Fatal("publication retry charged a second attempt")
	}
}

type heldResultProbe struct{ starts, cancelled, drain chan struct{} }

func (p heldResultProbe) Run(ctx context.Context, _ target, _ probePlan) snapshot {
	p.starts <- struct{}{}
	<-ctx.Done()
	close(p.cancelled)
	<-p.drain
	return useful(time.Now(), "")
}
func TestResetFencesIntakeAndLateUsefulResult(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := heldResultProbe{make(chan struct{}, 1), make(chan struct{}), make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	observe(c, session, "9.9.9.9", 2_000_000)
	select {
	case <-p.starts:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	observe(c, session, "8.8.8.8", 2_000_000)
	if err := c.ResetContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("not cancelled")
	}
	close(p.drain)
	eventually(t, func() bool {
		return c.Status().Running == 0 && len(c.Status().Targets) == 1 && c.Status().Targets[0].State == "cancelled"
	})
	if len(routeRows(t, app)) != 0 || len(runRows(t, app)) != 1 {
		t.Fatal("late result escaped reset or quota was refunded")
	}
}
func TestCloseWaitsForPhysicalDrainAndCanBeRetried(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := heldResultProbe{make(chan struct{}, 1), make(chan struct{}), make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	observe(c, session, "9.9.9.9", 2_000_000)
	select {
	case <-p.starts:
	case <-time.After(time.Second):
		t.Fatal("not started")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := c.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatal(err)
	}
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("not cancelled")
	}
	if err := c.Measure(context.Background(), "any"); err == nil {
		t.Fatal("closed coordinator accepted work")
	}
	close(p.drain)
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := c.ResetContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	if rows := runRows(t, app); len(rows) != 1 || rows[0].Status != "interrupted" {
		t.Fatal(rows)
	}
}
func TestResetTimeoutDoesNotAcknowledgeActivePublication(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	entered, release := make(chan struct{}), make(chan struct{})
	app.OnRecordCreate("route_evidence").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("kind") == "path" {
			close(entered)
			<-release
		}
		return e.Next()
	})
	c := startTestCoordinator(t, app, session, &terminalProbe{})
	observe(c, session, "9.9.9.9", 2_000_000)
	select {
	case <-entered:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("publication not entered")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	err := c.ResetContext(ctx)
	cancel()
	close(release)
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unsafe acknowledgement: %v", err)
	}
	if err := c.ResetContext(context.Background()); err != nil {
		t.Fatal(err)
	}
}
func TestManualMeasurementUsesObservedChunkAndSeparateQuota(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.ManualAttempts = 1
	p := &terminalProbe{}
	c := startTestCoordinator(t, app, session, p, cfg)
	chunk := data.TrafficChunk{ID: data.NewID(), Session: session, NetworkEpoch: c.NetworkEpoch(), DestinationIP: "9.9.9.9", Protocol: "tcp", DestinationPort: 443, StartMS: time.Now().UnixMilli(), Samples: []data.Sample{}}
	if _, err := data.Write(app, "traffic_chunks", chunk); err != nil {
		t.Fatal(err)
	}
	if err := c.Measure(context.Background(), "absent"); err == nil {
		t.Fatal("unobserved manual target accepted")
	}
	if err := c.Measure(context.Background(), chunk.ID); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return c.Status().Starts == 1 && c.Status().Running == 0 })
	if err := c.Measure(context.Background(), chunk.ID); err != nil {
		t.Fatal(err)
	}
	after := time.Now().Add(50 * time.Millisecond).UnixMilli()
	eventually(t, func() bool { return c.Status().UpdatedMS > after && c.Status().ManualRemaining == 0 })
	if len(runRows(t, app)) != 1 {
		t.Fatal("manual quota exceeded")
	}
}

type methodProbe struct{ methods chan string }

func (p methodProbe) Run(_ context.Context, _ target, plan probePlan) snapshot {
	p.methods <- plan.Method
	now := time.Now()
	return snapshot{Method: plan.Method, Measured: now, Finished: now, Status: "unavailable"}
}
func TestComparisonContinuesAfterTrafficExpires(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	old := time.Now().Add(-61 * time.Second)
	b := bindingFor(t, r, session, "9.9.9.9", old)
	a := mustReserve(t, r, b, false, old)
	if err := r.finish(a, snapshot{Method: a.Method, Measured: old, Finished: old, Status: "unavailable"}, old, true); err != nil {
		t.Fatal(err)
	}
	p := methodProbe{make(chan string, 2)}
	c := startTestCoordinator(t, app, session, p)
	c.Observe(Traffic{Session: session, NetworkEpoch: c.NetworkEpoch(), IP: b.Target.IP, Protocol: "tcp", Port: 443, Bytes: 1, At: old})
	select {
	case method := <-p.methods:
		if method != "icmp-paris" {
			t.Fatal(method)
		}
	case <-time.After(time.Second):
		t.Fatal("admitted comparison stalled without another burst")
	}
	eventually(t, func() bool { return c.Status().Running == 0 })
	if len(runRows(t, app)) != 2 {
		t.Fatal("comparison exceeded two methods")
	}
}

type drainingProbe struct {
	starts           chan string
	cancelled, drain chan struct{}
	active, peak     atomic.Int32
}

func (p *drainingProbe) Run(ctx context.Context, target target, _ probePlan) snapshot {
	n := p.active.Add(1)
	defer p.active.Add(-1)
	for old := p.peak.Load(); n > old && !p.peak.CompareAndSwap(old, n); old = p.peak.Load() {
	}
	p.starts <- target.IP
	if target.IP == "9.9.9.9" {
		<-ctx.Done()
		close(p.cancelled)
		<-p.drain
	}
	return useful(time.Now(), "")
}
func TestResetKeepsPhysicalLeaseUntilCancelledWorkerDrains(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	p := &drainingProbe{starts: make(chan string, 2), cancelled: make(chan struct{}), drain: make(chan struct{})}
	c := startTestCoordinator(t, app, session, p)
	observe(c, session, "9.9.9.9", 2_000_000)
	select {
	case <-p.starts:
	case <-time.After(time.Second):
		t.Fatal("first probe not started")
	}
	if err := c.ResetContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-p.cancelled:
	case <-time.After(time.Second):
		t.Fatal("probe not cancelled")
	}
	observe(c, session, "8.8.8.8", 2_000_000)
	select {
	case <-p.starts:
		t.Fatal("physical workers overlapped during cancellation")
	case <-time.After(100 * time.Millisecond):
	}
	close(p.drain)
	select {
	case ip := <-p.starts:
		if ip != "8.8.8.8" {
			t.Fatal(ip)
		}
	case <-time.After(time.Second):
		t.Fatal("replacement never started after drain")
	}
	eventually(t, func() bool { return c.Status().Running == 0 })
	if p.peak.Load() != 1 || len(runRows(t, app)) != 2 {
		t.Fatal("worker or admission limit broken")
	}
}
func TestFingerprintFailureSuspendsAdmissionAndRecoveryKeepsEpoch(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	var failed atomic.Bool
	p := &terminalProbe{}
	c := startCoordinatorWithNetwork(t, app, session, p, defaultConfig(), func() (string, error) {
		if failed.Load() {
			return "", errors.New("routing unavailable")
		}
		return "network", nil
	})
	epoch := c.NetworkEpoch()
	failed.Store(true)
	eventually(t, func() bool { return c.NetworkEpoch() == "" && c.Status().Network == "unknown" })
	c.Observe(Traffic{Session: session, NetworkEpoch: epoch, IP: "8.8.8.8", Protocol: "tcp", Port: 443, Bytes: 2_000_000, At: time.Now()})
	time.Sleep(100 * time.Millisecond)
	if p.starts.Load() != 0 || len(runRows(t, app)) != 0 {
		t.Fatal("admitted against an unavailable fingerprint")
	}
	failed.Store(false)
	eventually(t, func() bool { return c.NetworkEpoch() == epoch })
	observe(c, session, "8.8.8.8", 2_000_000)
	eventually(t, func() bool { return c.Status().Running == 0 && len(routeRows(t, app)) == 1 })
	if err := c.ResetContext(context.Background()); err != nil {
		t.Fatal(err)
	}
	eventually(t, func() bool { return len(c.Status().Targets) == 1 && c.Status().Targets[0].State == "useful_path" })
	if c.Status().Attempts != 1 {
		t.Fatal("reset lost durable attempt status")
	}
}
