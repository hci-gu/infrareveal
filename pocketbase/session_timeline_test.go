package main

import (
	"encoding/json"
	"strconv"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func TestTimelineLODAndActivityAggregation(t *testing.T) {
	label, bucket, overview, err := parseTimelineLOD("500ms")
	if err != nil || label != "500ms" || bucket != 500 || overview {
		t.Fatalf("unexpected lod result: %q %d %v %v", label, bucket, overview, err)
	}
	record := map[string]any{
		"bucket_ms": 50,
		"samples": map[string]any{
			"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
			"samples": [][]int64{{0, 10, 0, 1, 0}, {50, 0, 20, 0, 2}, {500, 5, 5, 1, 1}},
		},
	}
	aggregated := aggregateActivityRecord(record, 500)
	raw, _ := json.Marshal(aggregated["samples"])
	payload := activitySamplePayload{}
	if err := json.Unmarshal(raw, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.BucketMS != 500 || len(payload.Samples) != 2 {
		t.Fatalf("unexpected aggregate: %#v", payload)
	}
	if payload.Samples[0][1] != 10 || payload.Samples[0][2] != 20 || payload.Samples[0][3] != 1 || payload.Samples[0][4] != 2 {
		t.Fatalf("unexpected first aggregate bin: %#v", payload.Samples[0])
	}
}

func TestSessionTimelineManifestAndWindow(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })

	start := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	sessionCollection, _ := app.FindCollectionByNameOrId("sessions")
	session := core.NewRecord(sessionCollection)
	session.Set("name", "Timeline test")
	session.Set("active", true)
	session.Set("started_at", start.Format(time.RFC3339Nano))
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	if session.GetDateTime("created").IsZero() || session.GetDateTime("updated").IsZero() {
		t.Fatalf("session revision fields were not populated: created=%q updated=%q", session.GetString("created"), session.GetString("updated"))
	}

	flowCollection, _ := app.FindCollectionByNameOrId("flows")
	flow := core.NewRecord(flowCollection)
	flow.Set("session", session.Id)
	flow.Set("flow_key", "tcp|10.0.0.50|53000|93.184.216.34|443")
	flow.Set("client_ip", "10.0.0.50")
	flow.Set("destination_ip", "93.184.216.34")
	flow.Set("source_port", 53000)
	flow.Set("destination_port", 443)
	flow.Set("protocol", "tcp")
	flow.Set("start", start.Add(time.Second).Format(time.RFC3339Nano))
	flow.Set("last_seen", start.Add(4*time.Second).Format(time.RFC3339Nano))
	if err := app.Save(flow); err != nil {
		t.Fatal(err)
	}
	if flow.GetDateTime("created").IsZero() || flow.GetDateTime("updated").IsZero() {
		t.Fatalf("flow revision fields were not populated: created=%q updated=%q", flow.GetString("created"), flow.GetString("updated"))
	}

	chunkCollection, _ := app.FindCollectionByNameOrId("flow_activity_chunks")
	chunk := core.NewRecord(chunkCollection)
	chunk.Set("session", session.Id)
	chunk.Set("flow", flow.Id)
	chunk.Set("chunk_key", "timeline-test")
	chunk.Set("flow_key", flow.GetString("flow_key"))
	chunk.Set("chunk_start", start.Format(time.RFC3339Nano))
	chunk.Set("bucket_ms", 50)
	chunk.Set("chunk_ms", 5000)
	chunk.Set("samples", map[string]any{
		"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
		"samples": [][]int64{{1000, 10, 20, 1, 2}, {1050, 5, 5, 1, 1}},
	})
	if err := app.Save(chunk); err != nil {
		t.Fatal(err)
	}

	manifest, err := buildSessionTimelineManifest(app, session.Id, start.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SessionID != session.Id || manifest.Counts["flows"] != 1 || manifest.Counts["flow_activity_chunks"] != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}

	window, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from": {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":   {strconv.FormatInt(start.Add(10*time.Second).UnixMilli(), 10)},
		"lod":  {"500ms"},
	})
	if err != nil || status != 200 {
		t.Fatalf("window failed: status=%d err=%v", status, err)
	}
	if len(window.Flows) != 1 || len(window.FlowActivityChunks) != 1 {
		t.Fatalf("unexpected window counts: flows=%d chunks=%d", len(window.Flows), len(window.FlowActivityChunks))
	}
	if window.FlowActivityChunks[0]["bucket_ms"] != 500 {
		t.Fatalf("expected server LOD aggregation, got %#v", window.FlowActivityChunks[0]["bucket_ms"])
	}

	otherFlow := core.NewRecord(flowCollection)
	otherFlow.Set("session", session.Id)
	otherFlow.Set("flow_key", "tcp|10.0.0.51|53001|1.1.1.1|443")
	otherFlow.Set("client_ip", "10.0.0.51")
	otherFlow.Set("destination_ip", "1.1.1.1")
	otherFlow.Set("source_port", 53001)
	otherFlow.Set("destination_port", 443)
	otherFlow.Set("protocol", "tcp")
	otherFlow.Set("start", start.Add(2*time.Second).Format(time.RFC3339Nano))
	otherFlow.Set("last_seen", start.Add(5*time.Second).Format(time.RFC3339Nano))
	if err := app.Save(otherFlow); err != nil {
		t.Fatal(err)
	}

	filtered, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from": {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":   {strconv.FormatInt(start.Add(10*time.Second).UnixMilli(), 10)},
		"lod":  {"50ms"},
		"flow": {flow.Id},
	})
	if err != nil || status != 200 {
		t.Fatalf("filtered window failed: status=%d err=%v", status, err)
	}
	if len(filtered.Flows) != 1 || filtered.Flows[0]["id"] != flow.Id || len(filtered.FlowActivityChunks) != 1 {
		t.Fatalf("expected only the requested flow and activity, got flows=%#v chunks=%d", filtered.Flows, len(filtered.FlowActivityChunks))
	}

	overview, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from": {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":   {strconv.FormatInt(start.Add(time.Hour).UnixMilli(), 10)},
		"lod":  {"overview"},
	})
	if err != nil || status != 200 || len(overview.FlowActivityChunks) != 0 {
		t.Fatalf("overview should omit raw activity: status=%d err=%v chunks=%d", status, err, len(overview.FlowActivityChunks))
	}
}
