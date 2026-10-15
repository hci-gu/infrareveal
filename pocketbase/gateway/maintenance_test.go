package gateway

import (
	"strings"
	"testing"
	"time"

	"myapp/data"
	"myapp/observer"
	"myapp/testsupport"
)

func TestDiagnosticsHaveIndependentAgeAndPayloadBounds(t *testing.T) {
	app := testsupport.App(t)
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	g := testRuntime(t, app)
	g.config.DiagnosticMaxBytes = 6000
	g.config.DiagnosticRetention = time.Hour
	now := time.Now()
	old := testsupport.Save(t, app, "dns_queries", map[string]any{"query_name": "old.test", "observed_ms": now.Add(-2 * time.Hour).UnixMilli()})
	for i := 0; i < 5; i++ {
		testsupport.Save(t, app, "dns_queries", map[string]any{"query_name": "recent.test", "observed_ms": now.UnixMilli(), "answers": []string{strings.Repeat("x", 900)}})
	}
	pending := testsupport.Save(t, app, "gate_events", map[string]any{"session": "fixture", "decision_id": "pending", "state": "queued", "queued_at": now.Add(-2 * time.Hour)})
	terminal := testsupport.Save(t, app, "gate_events", map[string]any{"session": "fixture", "decision_id": "terminal", "state": "approved", "queued_at": now.Add(-2 * time.Hour)})
	if err := g.pruneDiagnostics(now); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindRecordById("dns_queries", old.Id); err == nil {
		t.Fatal("expired diagnostic retained")
	}
	count, err := app.CountRecords("dns_queries")
	if err != nil || count == 0 || count >= 5 {
		t.Fatalf("payload cap did not retain a bounded recent tail: %d %v", count, err)
	}
	if _, err := app.FindRecordById("gate_events", pending.Id); err != nil {
		t.Fatal("evicted pending gate verdict", err)
	}
	if _, err := app.FindRecordById("gate_events", terminal.Id); err == nil {
		t.Fatal("expired terminal audit retained")
	}
}

func TestRetentionFailureDoesNotSuspendQuotaOrDiagnosticCleanup(t *testing.T) {
	app := testsupport.App(t)
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := now.Add(-7 * 24 * time.Hour).UnixMilli()
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "ephemeral": true, "started_ms": old, "retention_minutes": 30, "policy": observer.DefaultPolicy()})
	chunk := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "start_ms": old, "chunk_ms": 5000, "bucket_ms": 50, "samples": []data.Sample{{0, 60, 0, 0, 0, 1, 0}}})
	admission := testsupport.Save(t, app, "probe_runs", map[string]any{"session": "deleted", "admitted_ms": old})
	diagnostic := testsupport.Save(t, app, "dns_queries", map[string]any{"session": session.Id, "query_name": "expired.test", "observed_ms": old})
	if _, err := app.DB().NewQuery("CREATE TRIGGER reject_retention BEFORE DELETE ON traffic_chunks BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").Execute(); err != nil {
		t.Fatal(err)
	}
	if err := testRuntime(t, app).sweep(now); err == nil {
		t.Fatal("retention failure was hidden")
	}
	if _, err := app.FindRecordById("traffic_chunks", chunk.Id); err != nil {
		t.Fatal("failed retention removed traffic", err)
	}
	if _, err := app.FindRecordById("probe_runs", admission.Id); err == nil {
		t.Fatal("unrelated expired quota retained")
	}
	if _, err := app.FindRecordById("dns_queries", diagnostic.Id); err == nil {
		t.Fatal("unrelated diagnostic cleanup blocked")
	}
}
