package gateway

import (
	"context"
	"testing"
	"time"

	"myapp/data"
	"myapp/testsupport"
)

func TestClearIsAtomicAndPreservesSessionsAndProbeAdmissions(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "clear", "active": true})
	destination := testsupport.Save(t, app, "destinations", map[string]any{"ip": "1.1.1.1", "version": "fixture"})
	chunk := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "destination_id": destination.Id, "start_ms": time.Now().UnixMilli(), "bucket_ms": 50, "chunk_ms": 5000, "samples": []data.Sample{{0, 60, 0, 0, 0, 1, 0}}})
	admission := testsupport.Save(t, app, "probe_runs", map[string]any{"session": session.Id, "admitted_ms": time.Now().UnixMilli(), "status": "running"})
	// A failure midway through deletion must leave the complete old view intact.
	if _, err := app.DB().NewQuery("CREATE TRIGGER reject_chunk_clear BEFORE DELETE ON traffic_chunks BEGIN SELECT RAISE(ABORT, 'fixture failure'); END").Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Clear(context.Background()); err == nil {
		t.Fatal("expected transactional clear failure")
	}
	if _, err := app.FindRecordById("traffic_chunks", chunk.Id); err != nil {
		t.Fatal("failed clear removed traffic", err)
	}
	current, err := app.FindRecordById("sessions", session.Id)
	if err != nil || current.GetInt64("revision") != session.GetInt64("revision") {
		t.Fatal("failed clear changed revision", err)
	}
	if _, err := app.DB().NewQuery("DROP TRIGGER reject_chunk_clear").Execute(); err != nil {
		t.Fatal(err)
	}
	before := time.Now().UnixMilli()
	result, err := g.Clear(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted["traffic_chunks"] != 1 || result.Deleted["destinations"] != 1 || len(result.Skipped) != 3 {
		t.Fatalf("wrong clear result: %+v", result)
	}
	if _, err := app.FindRecordById("probe_runs", admission.Id); err != nil {
		t.Fatal("clear refunded a durable probe admission", err)
	}
	current, err = app.FindRecordById("sessions", session.Id)
	floor := current.GetInt64("retained_from_ms")
	if err != nil || g.CurrentSessionID() != session.Id || current.GetInt64("revision") != session.GetInt64("revision")+1 || floor < before/50*50 || floor%50 != 0 || current.GetInt64("block_watermark_ms") != 0 {
		t.Fatal("clear did not publish retained edge", err)
	}
}

func TestSessionDeleteCleansTextReferencesAndKeepsQuota(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "delete", "active": true})
	other := testsupport.Save(t, app, "sessions", map[string]any{"name": "keep"})
	destination := testsupport.Save(t, app, "destinations", map[string]any{"ip": "1.1.1.1", "version": "shared"})
	for _, id := range []string{session.Id, other.Id} {
		testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": id, "destination_id": destination.Id})
		for _, collection := range []string{"capture_intervals", "activity_blocks", "flow_diagnostics", "dns_queries", "gate_events"} {
			testsupport.Save(t, app, collection, map[string]any{"session": id})
		}
		testsupport.Save(t, app, "route_evidence", map[string]any{"session": id, "kind": "network_invalidated"})
	}
	admission := testsupport.Save(t, app, "probe_runs", map[string]any{"session": session.Id})
	if err := app.Delete(session); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() != "" {
		t.Fatal("deleted session remained installed")
	}
	for _, collection := range []string{"traffic_chunks", "capture_intervals", "activity_blocks", "route_evidence", "flow_diagnostics", "dns_queries", "gate_events"} {
		count, err := app.CountRecords(collection)
		if err != nil || count != 1 {
			t.Fatalf("%s retained deleted session data: count=%d err=%v", collection, count, err)
		}
	}
	if _, err := app.FindRecordById("probe_runs", admission.Id); err != nil {
		t.Fatal("deleting session refunded quotas", err)
	}
	if _, err := app.FindRecordById("destinations", destination.Id); err != nil {
		t.Fatal("deleted shared destination", err)
	}
	if err := app.Delete(other); err != nil {
		t.Fatal(err)
	}
	if count, _ := app.CountRecords("destinations"); count != 0 {
		t.Fatal("unreferenced destination not collected")
	}
}
