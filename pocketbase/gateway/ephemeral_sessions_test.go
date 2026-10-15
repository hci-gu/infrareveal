package gateway

import (
	"fmt"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"myapp/data"
	"myapp/observer"
	"myapp/testsupport"
	"myapp/timeline"
)

func testRuntime(t *testing.T, app *pocketbase.PocketBase) *Runtime {
	t.Helper()
	config, err := ConfigFromEnv()
	if err != nil {
		t.Fatal(err)
	}
	return New(app, config)
}

func TestEphemeralRetentionPreservesIdentityAndRecordedHistory(t *testing.T) {
	app := testsupport.App(t)
	now := time.UnixMilli(1700003600012)
	start := now.Add(-time.Hour).Truncate(50 * time.Millisecond).UnixMilli()
	policy := observer.DefaultPolicy()
	rolling := testsupport.Save(t, app, "sessions", map[string]any{"name": "rolling", "active": true, "ephemeral": true, "started_ms": start, "retention_minutes": 30, "policy": policy})
	saved := testsupport.Save(t, app, "sessions", map[string]any{"name": "saved", "started_ms": start, "ended_ms": start + 10000, "retention_minutes": 30, "policy": policy})
	cutoff := (now.Add(-30*time.Minute).UnixMilli() + 49) / 50 * 50
	for _, id := range []string{rolling.Id, saved.Id} {
		testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": id, "client_id": "client", "service_key": "svt.se", "start_ms": start, "chunk_ms": 5000, "bucket_ms": 50, "samples": []data.Sample{{0, 100, 0, 40, 0, 1, 0}}})
	}
	recent := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": rolling.Id, "client_id": "client", "service_key": "svt.se", "start_ms": cutoff, "chunk_ms": 5000, "bucket_ms": 50, "samples": []data.Sample{{0, 200, 0, 40, 0, 1, 0}}})
	if err := testRuntime(t, app).pruneEphemeralSessions(now); err != nil {
		t.Fatal(err)
	}
	rows, err := app.FindRecordsByFilter("traffic_chunks", "", "", 0, 0)
	if err != nil || len(rows) != 2 {
		t.Fatalf("retention removed saved data or retained old rolling data: %d %v", len(rows), err)
	}
	if _, err := app.FindRecordById("traffic_chunks", recent.Id); err != nil {
		t.Fatal(err)
	}
	manifest, err := timeline.New(app).Manifest(rolling.Id, now)
	if err != nil || manifest.StartedMS != start || manifest.RetainedFromMS != cutoff || !manifest.Active {
		t.Fatalf("retention changed identity: %+v %v", manifest, err)
	}
	rolling, _ = app.FindRecordById("sessions", rolling.Id)
	rolling.Set("active", false)
	rolling.Set("ended_ms", now.UnixMilli())
	normalizeEphemeralSession(rolling, now.Add(time.Hour))
	if rolling.GetBool("active") || rolling.GetInt64("retained_from_ms") != cutoff {
		t.Fatal("normalization reopened or expired a closed recording")
	}
}

func TestEphemeralTrafficStoragePlateaus(t *testing.T) {
	app := testsupport.App(t)
	start := time.UnixMilli(1700000000000)
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "ephemeral": true, "started_ms": start.UnixMilli(), "retention_minutes": 1, "policy": observer.DefaultPolicy()})
	runtime := testRuntime(t, app)
	for second := 0; second < 180; second += 5 {
		at := start.Add(time.Duration(second) * time.Second)
		testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "client_id": "client", "service_key": "endpoint:" + fmt.Sprint(second), "start_ms": at.UnixMilli(), "chunk_ms": 5000, "bucket_ms": 50, "samples": []data.Sample{{0, 60, 0, 0, 0, 1, 0}}})
		if err := runtime.pruneEphemeralSessions(at); err != nil {
			t.Fatal(err)
		}
		count, err := app.CountRecords("traffic_chunks")
		if err != nil || count > 13 {
			t.Fatalf("rolling chunks grew to %d at %d seconds: %v", count, second, err)
		}
	}
}
