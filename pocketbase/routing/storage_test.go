package routing

import (
	"errors"
	"fmt"
	"myapp/data"
	"myapp/testsupport"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

func testSession(t *testing.T, app core.App) string {
	t.Helper()
	return testsupport.Save(t, app, "sessions", map[string]any{"active": true, "started_ms": time.Now().Add(-time.Minute).UnixMilli()}).Id
}
func bindingFor(t *testing.T, r evidenceStore, session, ip string, now time.Time) routeBinding {
	t.Helper()
	epoch, err := r.activateNetwork(session, "network", now)
	if err != nil {
		t.Fatal(err)
	}
	return routeBinding{Session: session, Network: "network", Epoch: epoch, Target: target{ip, "tcp", 443}}
}
func mustReserve(t *testing.T, r evidenceStore, b routeBinding, manual bool, now time.Time) admission {
	t.Helper()
	a, err := r.reserve(b, manual, now)
	if err != nil || a.Reason != "" {
		t.Fatalf("admission: %+v %v", a, err)
	}
	return a
}
func useful(at time.Time, attempt string) snapshot {
	return snapshot{Attempt: attempt, Revision: 1, Method: "tcp:443", Measured: at, Started: at, Finished: at, Status: "reached", Reached: true, ProbedTTL: 13, Hops: []Hop{{TTL: 1, Address: "192.168.1.1", State: "reply"}, {TTL: 2, Address: "1.1.1.1", State: "reply"}, {TTL: 8, Address: "8.8.4.4", State: "reply"}, {TTL: 13, Address: "9.9.9.9", State: "reply"}}}
}
func routeRows(t *testing.T, app core.App) []data.RouteEvidence {
	t.Helper()
	rows, err := app.FindAllRecords("route_evidence")
	if err != nil {
		t.Fatal(err)
	}
	result := []data.RouteEvidence{}
	for _, row := range rows {
		value, err := data.Decode[data.RouteEvidence](row)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	return result
}
func runRows(t *testing.T, app core.App) []data.ProbeRun {
	t.Helper()
	rows, err := app.FindAllRecords("probe_runs")
	if err != nil {
		t.Fatal(err)
	}
	result := []data.ProbeRun{}
	for _, row := range rows {
		value, err := data.Decode[data.ProbeRun](row)
		if err != nil {
			t.Fatal(err)
		}
		result = append(result, value)
	}
	return result
}
func TestAdmissionChargeSurvivesRestartAndSessionDeletion(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.HourlyAttempts = 1
	r := newEvidenceStore(app, nil, cfg)
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	if err := r.recoverAdmissions(now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if got := runRows(t, app); len(got) != 1 || got[0].Status != "interrupted" {
		t.Fatal(got)
	}
	rec, _ := app.FindRecordById("sessions", session)
	if err := app.Delete(rec); err != nil {
		t.Fatal(err)
	}
	next := testSession(t, app)
	b = bindingFor(t, r, next, "8.8.8.8", now)
	denied, err := r.reserve(b, false, now.Add(2*time.Second))
	if err != nil || denied.Reason != "hourly_budget" {
		t.Fatalf("reset budget after delete: %+v %v", denied, err)
	}
	if err := RetainShared(app, now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if rows := runRows(t, app); len(rows) != 1 || rows[0].ID != a.Attempt {
		t.Fatal(rows)
	}
	nextAttempt := mustReserve(t, r, b, false, now.Add(time.Hour+time.Second))
	if nextAttempt.SourcePort != a.SourcePort+1 {
		t.Fatal("restart/session deletion reused a recent synthetic source port")
	}
}
func TestAdmissionTransactionCannotOverspend(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.MaxTargets = 1
	r := newEvidenceStore(app, nil, cfg)
	now := time.Now()
	base := bindingFor(t, r, session, "9.9.9.9", now)
	var admitted atomic.Int32
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			b := base
			b.Target.IP = fmt.Sprintf("9.9.9.%d", i+1)
			a, err := r.reserve(b, false, now)
			if err != nil {
				t.Error(err)
			} else if a.Reason == "" {
				admitted.Add(1)
			}
		}(i)
	}
	wg.Wait()
	if admitted.Load() != 1 || len(runRows(t, app)) != 1 {
		t.Fatalf("overspent: %d", admitted.Load())
	}
}
func TestFiniteMethodComparisonAndFiveFailurePause(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	base := bindingFor(t, r, session, "9.9.9.1", now)
	for i := 0; i < 5; i++ {
		b := base
		b.Target.IP = fmt.Sprintf("9.9.9.%d", i+1)
		for method := 0; method < 2; method++ {
			a := mustReserve(t, r, b, false, now)
			if a.Method != probeMethods(b.Target)[method] {
				t.Fatal(a)
			}
			s := snapshot{Method: a.Method, Measured: now, Finished: now, Status: "unavailable"}
			if err := r.finish(a, s, now, true); err != nil {
				t.Fatal(err)
			}
			now = now.Add(time.Second)
		}
	}
	if len(routeRows(t, app)) != 0 {
		t.Fatal("silent comparisons created paths")
	}
	b := base
	b.Target.IP = "8.8.8.8"
	denied, err := r.reserve(b, false, now)
	if err != nil || denied.Reason != "visibility_paused" {
		t.Fatalf("five comparisons did not pause: %+v %v", denied, err)
	}
	now = now.Add(31 * time.Minute)
	a := mustReserve(t, r, b, false, now)
	if err := r.finish(a, snapshot{Method: a.Method, Measured: now, Finished: now, Status: "unavailable"}, now, true); err != nil {
		t.Fatal(err)
	}
	b.Target.IP = "8.8.4.4"
	denied, err = r.reserve(b, false, now.Add(time.Second))
	if err != nil || denied.Reason != "visibility_paused" {
		t.Fatalf("failed trial did not restore pause: %+v %v", denied, err)
	}
}
func TestTerminalPublicationAndOneEnrichmentPreserveAge(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	s := useful(now, a.Attempt)
	s.Finished = time.Time{}
	if err := r.finish(a, s, now, true); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 0 {
		t.Fatal("progress persisted")
	}
	s.Finished = now
	if err := r.finish(a, s, now.Add(time.Second), true); err != nil {
		t.Fatal(err)
	}
	if err := r.finish(a, s, now.Add(2*time.Second), true); err != nil {
		t.Fatal(err)
	}
	rows := routeRows(t, app)
	if len(rows) != 1 || rows[0].MeasuredMS != now.UnixMilli() {
		t.Fatal(rows)
	}
	original := rows[0]
	s.Hops[2].Evidence = map[string]InterfaceEvidence{"8.8.4.4": {PTR: "example.test", Source: "DNS PTR", AvailableMS: now.Add(2 * time.Second).UnixMilli()}}
	if err := r.enrichPublication(a, s, now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if err := r.enrichPublication(a, s, now.Add(4*time.Second)); err != nil {
		t.Fatal(err)
	}
	rows = routeRows(t, app)
	if len(rows) != 2 {
		t.Fatal(rows)
	}
	for _, row := range rows {
		if row.MeasuredMS != original.MeasuredMS || row.ValidUntilMS != original.ValidUntilMS {
			t.Fatal("enrichment refreshed old measurement")
		}
	}
	before := EvidenceAt(rows, b.Epoch, b.Target.binding(), now.Add(2*time.Second).UnixMilli())
	after := EvidenceAt(rows, b.Epoch, b.Target.binding(), now.Add(4*time.Second).UnixMilli())
	if before == nil || before.Revision != 1 || after == nil || after.Revision != 2 {
		t.Fatalf("future enrichment leaked: %+v %+v", before, after)
	}
	if EvidenceAt(rows, b.Epoch, b.Target.binding(), original.ValidUntilMS) != nil {
		t.Fatal("expired path resurrected")
	}
	denied, err := r.reserve(b, false, now.Add(2*time.Hour))
	if err != nil || denied.Reason != "useful_path_saved" {
		t.Fatalf("recorded lifetime comparison restarted: %+v %v", denied, err)
	}
}
func TestPublicationRollbackKeepsAdmissionAndRetriesOnce(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	var failures atomic.Int32
	app.OnRecordUpdate("probe_runs").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("status") != "admitted" && failures.CompareAndSwap(0, 1) {
			return errors.New("injected final save failure")
		}
		return e.Next()
	})
	if err := r.finish(a, useful(now, a.Attempt), now, true); err == nil {
		t.Fatal("expected rollback")
	}
	if len(routeRows(t, app)) != 0 || runRows(t, app)[0].Status != "admitted" {
		t.Fatal("partial publication escaped transaction")
	}
	if err := r.finish(a, useful(now, a.Attempt), now, true); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 1 || len(runRows(t, app)) != 1 {
		t.Fatal("retry duplicated admission/publication")
	}
}
func TestNetworkEpochInvalidatesAndRestartKeepsCurrentEpoch(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	if err := r.finish(a, useful(now, a.Attempt), now, true); err != nil {
		t.Fatal(err)
	}
	same, err := r.activateNetwork(session, "network", now.Add(time.Second))
	if err != nil || same != b.Epoch {
		t.Fatalf("restart changed epoch: %s %v", same, err)
	}
	next, err := r.activateNetwork(session, "changed", now.Add(2*time.Second))
	if err != nil || next == b.Epoch {
		t.Fatal(next, err)
	}
	rows := routeRows(t, app)
	if EvidenceAt(rows, b.Epoch, b.Target.binding(), now.Add(time.Second).UnixMilli()) == nil {
		t.Fatal("invalidation affected earlier playback")
	}
	if EvidenceAt(rows, b.Epoch, b.Target.binding(), now.Add(2*time.Second).UnixMilli()) != nil {
		t.Fatal("old network evidence survived invalidation")
	}
	if err := r.enrichPublication(a, useful(now, a.Attempt), now.Add(3*time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 2 {
		t.Fatal("late enrichment resurrected old epoch")
	}
}
func TestContinuousScopeRenewsWithoutRefundingNetworkBudget(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	rec, _ := app.FindRecordById("sessions", session)
	now := time.Now().Truncate(time.Millisecond)
	rec.Set("ephemeral", true)
	rec.Set("started_ms", now.Add(-time.Hour+time.Second).UnixMilli())
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}
	cfg := defaultConfig()
	cfg.MaxAttempts = 1
	cfg.HourlyAttempts = 1
	r := newEvidenceStore(app, nil, cfg)
	b := bindingFor(t, r, session, "9.9.9.9", now)
	mustReserve(t, r, b, false, now)
	b.Target.IP = "8.8.8.8"
	denied, err := r.reserve(b, false, now.Add(2*time.Second))
	if err != nil || denied.Reason != "hourly_budget" {
		t.Fatal(denied, err)
	}
	_ = mustReserve(t, r, b, false, now.Add(time.Hour+time.Second))
}
func TestProbeLedgerRetentionKeepsOpenRecordingAndRecentDeletedSession(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	now := time.Now()
	r := newEvidenceStore(app, nil, defaultConfig())
	b := bindingFor(t, r, session, "9.9.9.9", now.Add(-25*time.Hour))
	mustReserve(t, r, b, false, now.Add(-25*time.Hour))
	if err := RetainShared(app, now); err != nil {
		t.Fatal(err)
	}
	if len(runRows(t, app)) != 1 {
		t.Fatal("open recording lost lifetime charges")
	}
	rec, _ := app.FindRecordById("sessions", session)
	if err := app.Delete(rec); err != nil {
		t.Fatal(err)
	}
	if err := RetainShared(app, now); err != nil {
		t.Fatal(err)
	}
	if len(runRows(t, app)) != 0 {
		t.Fatal("expired deleted-session ledger retained")
	}
}
func TestEvidenceByteLimitStillSealsChargedAttempt(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.MaxBytes = 100
	r := newEvidenceStore(app, nil, cfg)
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	if err := r.finish(a, useful(now, a.Attempt), now, true); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 0 {
		t.Fatal("byte cap ignored")
	}
	runs := runRows(t, app)
	if len(runs) != 1 || runs[0].Status == "admitted" || runs[0].Class != "storage_limited" {
		t.Fatal(runs)
	}
}

func TestCrossSessionCooldownPersistsButUsefulPathsAreNotCopied(t *testing.T) {
	app := testsupport.App(t)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	session := testSession(t, app)
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	if err := r.finish(a, snapshot{Method: a.Method, Measured: now, Finished: now, Status: "unavailable"}, now, true); err != nil {
		t.Fatal(err)
	}
	rec, _ := app.FindRecordById("sessions", session)
	if err := app.Delete(rec); err != nil {
		t.Fatal(err)
	}
	session = testSession(t, app)
	b = bindingFor(t, r, session, "9.9.9.9", now.Add(time.Second))
	denied, err := r.reserve(b, false, now.Add(time.Second))
	if err != nil || denied.Reason != "method_cooldown" {
		t.Fatal(denied, err)
	}
	now = now.Add(31 * time.Minute)
	a = mustReserve(t, r, b, false, now)
	if err := r.finish(a, useful(now, a.Attempt), now, true); err != nil {
		t.Fatal(err)
	}
	rec, _ = app.FindRecordById("sessions", session)
	rec.Set("active", false)
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}
	next := testSession(t, app)
	b = bindingFor(t, r, next, "9.9.9.9", now.Add(time.Second))
	_ = mustReserve(t, r, b, false, now.Add(time.Second))
	paths := routeRows(t, app)
	if len(paths) != 1 || paths[0].Session != session {
		t.Fatal("cross-session path copy", paths)
	}
}
func TestOversizedOptionalDetailsDoNotBlockUsefulEvidenceAndStorageCap(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.Diagnostics = true
	cfg.MaxSnapshots = 1
	r := newEvidenceStore(app, nil, cfg)
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	s := useful(now, a.Attempt)
	s.StopReason = string(make([]byte, 17000))
	if err := r.finish(a, s, now, true); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 1 || runRows(t, app)[0].Details != nil {
		t.Fatal("optional oversized details prevented path/accounting")
	}
	denied, err := r.reserve(b, true, now.Add(time.Second))
	if err != nil || denied.Reason != "storage_budget" {
		t.Fatal(denied, err)
	}
	s.Hops[2].Evidence = map[string]InterfaceEvidence{"8.8.4.4": {PTR: "example.test"}}
	if err := r.enrichPublication(a, s, now.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if len(routeRows(t, app)) != 1 {
		t.Fatal("enrichment exceeded path cap")
	}
}
