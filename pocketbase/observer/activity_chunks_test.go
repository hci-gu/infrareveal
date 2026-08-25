package observer

import (
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"

	_ "myapp/migrations"
)

func TestPersistActivityChunkWaitsForFlowThenUpserts(t *testing.T) {
	app := newActivityTestApp(t)
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	snapshot := ActivityChunkSnapshot{
		Key: "chunk", SessionID: "", FlowKey: "tcp|10.0.0.50|53000|93.184.216.34|443",
		ChunkStart: start, BucketMS: 50, ChunkMS: 5000,
		Samples:      []ActivityBucket{{OffsetMS: 0, PayloadBytesOut: 80, PacketsOut: 1}},
		WireBytesOut: 120, PayloadBytesOut: 80, PacketsOut: 1,
		CaptureComplete: true, UpdatedAtSource: start,
	}
	session := createActivityTestSession(t, app, false)
	snapshot.SessionID = session.Id

	result, err := persistActivityChunk(app, snapshot)
	if err != nil || result != activityFlowPending {
		t.Fatalf("expected unresolved flow to remain pending, result=%v err=%v", result, err)
	}
	flow := createActivityTestFlow(t, app, session.Id, snapshot.FlowKey)
	result, err = persistActivityChunk(app, snapshot)
	if err != nil || result != activityPersisted {
		t.Fatalf("expected chunk persistence, result=%v err=%v", result, err)
	}

	records, err := app.FindAllRecords("flow_activity_chunks")
	if err != nil || len(records) != 1 {
		t.Fatalf("expected one activity chunk, records=%d err=%v", len(records), err)
	}
	if records[0].GetString("flow") != flow.Id || records[0].GetInt("bucket_ms") != 50 || records[0].GetInt("chunk_ms") != 5000 {
		t.Fatalf("unexpected persisted chunk: %#v", records[0])
	}

	snapshot.PayloadBytesOut = 160
	snapshot.Generation++
	if _, err := persistActivityChunk(app, snapshot); err != nil {
		t.Fatalf("update persisted chunk: %v", err)
	}
	records, _ = app.FindAllRecords("flow_activity_chunks")
	if len(records) != 1 || records[0].GetInt("payload_bytes_out") != 160 {
		t.Fatalf("expected an upsert rather than a duplicate, got %d records", len(records))
	}
}

func TestActivityRetentionPreservesActiveSessions(t *testing.T) {
	app := newActivityTestApp(t)
	old := time.Now().UTC().Add(-48 * time.Hour)
	active := createActivityTestSession(t, app, true)
	inactive := createActivityTestSession(t, app, false)
	createActivityTestChunkRecord(t, app, active.Id, createActivityTestFlow(t, app, active.Id, "tcp|10.0.0.50|1|1.1.1.1|443").Id, old)
	createActivityTestChunkRecord(t, app, inactive.Id, createActivityTestFlow(t, app, inactive.Id, "tcp|10.0.0.51|2|1.0.0.1|443").Id, old)

	deleted, err := pruneExpiredActivityChunks(app, time.Now().Add(-24*time.Hour), 200)
	if err != nil {
		t.Fatalf("prune activity chunks: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("expected one inactive-session chunk deleted, got %d", deleted)
	}
	records, _ := app.FindAllRecords("flow_activity_chunks")
	if len(records) != 1 || records[0].GetString("session") != active.Id {
		t.Fatalf("expected active-session chunk to remain, got %#v", records)
	}
}

func TestActivityCaptureWindowUpsertsByStableKey(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	if err := upsertActivityCaptureWindow(app, session.Id, start, 5*time.Second, true, 0, ""); err != nil {
		t.Fatalf("create capture window: %v", err)
	}
	if err := upsertActivityCaptureWindow(app, session.Id, start, 5*time.Second, true, 3, "queue pressure"); err != nil {
		t.Fatalf("update capture window: %v", err)
	}
	records, err := app.FindAllRecords("flow_activity_windows")
	if err != nil || len(records) != 1 {
		t.Fatalf("expected one upserted window, records=%d err=%v", len(records), err)
	}
	if records[0].GetString("window_key") != activityWindowKey(session.Id, start) || records[0].GetInt("dropped_events") != 3 || records[0].GetBool("capture_complete") {
		t.Fatalf("unexpected updated capture window: %#v", records[0])
	}
}

func newActivityTestApp(t *testing.T) *pocketbase.PocketBase {
	t.Helper()
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatalf("bootstrap PocketBase: %v", err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatalf("run app migrations: %v", err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	for _, collection := range []string{"flow_activity_chunks", "flow_activity_windows", "flow_activity_status"} {
		if _, err := app.FindCollectionByNameOrId(collection); err != nil {
			t.Fatalf("expected migrated collection %s: %v", collection, err)
		}
	}
	return app
}

func createActivityTestSession(t *testing.T, app *pocketbase.PocketBase, active bool) *core.Record {
	t.Helper()
	collection, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		t.Fatal(err)
	}
	record := core.NewRecord(collection)
	record.Set("name", "Activity test")
	record.Set("active", active)
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func createActivityTestFlow(t *testing.T, app *pocketbase.PocketBase, sessionID, key string) *core.Record {
	t.Helper()
	collection, err := app.FindCollectionByNameOrId("flows")
	if err != nil {
		t.Fatal(err)
	}
	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("flow_key", key)
	record.Set("client_ip", "10.0.0.50")
	record.Set("destination_ip", "93.184.216.34")
	record.Set("source_port", 53000)
	record.Set("destination_port", 443)
	record.Set("protocol", "tcp")
	record.Set("start", time.Now().UTC().Format(time.RFC3339Nano))
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}
	return record
}

func createActivityTestChunkRecord(t *testing.T, app *pocketbase.PocketBase, sessionID, flowID string, start time.Time) {
	t.Helper()
	collection, err := app.FindCollectionByNameOrId("flow_activity_chunks")
	if err != nil {
		t.Fatal(err)
	}
	record := core.NewRecord(collection)
	record.Set("session", sessionID)
	record.Set("flow", flowID)
	record.Set("chunk_key", activityChunkKey(sessionID, flowID, start))
	record.Set("flow_key", flowID)
	record.Set("chunk_start", start.UTC().Format(time.RFC3339Nano))
	record.Set("bucket_ms", 50)
	record.Set("chunk_ms", 5000)
	record.Set("samples", map[string]any{"version": 1, "bucket_ms": 50, "chunk_ms": 5000, "samples": [][]int64{}})
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}
}
