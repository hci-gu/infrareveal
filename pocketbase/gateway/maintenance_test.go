package gateway

import (
	"testing"
	"time"

	"myapp/data"
	"myapp/observer"
	"myapp/testsupport"
)

func TestRetentionFailureDoesNotSuspendQuotaCleanup(t *testing.T) {
	app := testsupport.App(t)
	now := time.Now()
	old := now.Add(-7 * 24 * time.Hour).UnixMilli()
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "ephemeral": true, "started_ms": old, "retention_minutes": 30, "policy": observer.DefaultPolicy()})
	chunk := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "start_ms": old, "chunk_ms": 5000, "bucket_ms": 50, "samples": []data.Sample{{0, 60, 0, 0, 0, 1, 0}}})
	admission := testsupport.Save(t, app, "probe_runs", map[string]any{"session": "deleted", "admitted_ms": old})
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
}
