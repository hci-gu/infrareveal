package main

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
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

func TestSessionTimelineWindowSupportsMoreThanFilterExpressionLimit(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })

	start := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	sessionCollection, _ := app.FindCollectionByNameOrId("sessions")
	session := core.NewRecord(sessionCollection)
	session.Set("name", "Large timeline test")
	session.Set("active", true)
	session.Set("started_at", start.Format(time.RFC3339Nano))
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}

	flowCollection, _ := app.FindCollectionByNameOrId("flows")
	flowIDs := make([]string, 0, 205)
	for index := 0; index < 205; index++ {
		flow := core.NewRecord(flowCollection)
		flow.Set("session", session.Id)
		flow.Set("flow_key", fmt.Sprintf("tcp|10.0.0.50|%d|198.51.%d.%d|443", 40000+index, index/250, index%250+1))
		flow.Set("client_ip", "10.0.0.50")
		flow.Set("destination_ip", fmt.Sprintf("198.51.%d.%d", index/250, index%250+1))
		flow.Set("source_port", 40000+index)
		flow.Set("destination_port", 443)
		flow.Set("protocol", "tcp")
		flow.Set("start", start.Add(time.Duration(index)*time.Millisecond).Format(time.RFC3339Nano))
		flow.Set("last_seen", start.Add(time.Minute).Format(time.RFC3339Nano))
		if err := app.Save(flow); err != nil {
			t.Fatal(err)
		}
		flowIDs = append(flowIDs, flow.Id)
	}

	attributionCollection, _ := app.FindCollectionByNameOrId("flow_attributions")
	attribution := core.NewRecord(attributionCollection)
	attribution.Set("session", session.Id)
	attribution.Set("flow", flowIDs[0])
	attribution.Set("candidate_hostname", "example.test")
	attribution.Set("source_signal", "dns")
	attribution.Set("confidence", "high")
	attribution.Set("observed_at", start.Format(time.RFC3339Nano))
	if err := app.Save(attribution); err != nil {
		t.Fatal(err)
	}

	episodeCollection, _ := app.FindCollectionByNameOrId("activity_episodes")
	episode := core.NewRecord(episodeCollection)
	episode.Set("session", session.Id)
	episode.Set("episode_key", "large-timeline-episode")
	episode.Set("client_ip", "10.0.0.50")
	episode.Set("site_key", "example.test")
	episode.Set("label", "Example")
	episode.Set("anchor_hostname", "example.test")
	episode.Set("start", start.Format(time.RFC3339Nano))
	episode.Set("last_seen", start.Add(time.Minute).Format(time.RFC3339Nano))
	episode.Set("confidence", "high")
	if err := app.Save(episode); err != nil {
		t.Fatal(err)
	}

	associationCollection, _ := app.FindCollectionByNameOrId("flow_associations")
	association := core.NewRecord(associationCollection)
	association.Set("session", session.Id)
	association.Set("flow", flowIDs[0])
	association.Set("episode", episode.Id)
	association.Set("parent_site_key", "example.test")
	association.Set("parent_label", "Example")
	association.Set("relationship", "first_party")
	association.Set("confidence", "high")
	association.Set("score", 100)
	association.Set("observed_at", start.Format(time.RFC3339Nano))
	if err := app.Save(association); err != nil {
		t.Fatal(err)
	}

	destinationCollection, _ := app.FindCollectionByNameOrId("destinations")
	destination := core.NewRecord(destinationCollection)
	destination.Set("ip", "198.51.0.1")
	destination.Set("reverse_dns", "example.test")
	destination.Set("first_seen", start.Format(time.RFC3339Nano))
	destination.Set("last_seen", start.Add(time.Minute).Format(time.RFC3339Nano))
	if err := app.Save(destination); err != nil {
		t.Fatal(err)
	}

	routeCollection, _ := app.FindCollectionByNameOrId("routes")
	route := core.NewRecord(routeCollection)
	route.Set("session", session.Id)
	route.Set("destination", destination.Id)
	route.Set("destination_ip", destination.GetString("ip"))
	route.Set("destination_port", 443)
	route.Set("protocol", "tcp")
	route.Set("method", "traceroute")
	route.Set("started_at", start.Format(time.RFC3339Nano))
	route.Set("completed_at", start.Add(time.Second).Format(time.RFC3339Nano))
	if err := app.Save(route); err != nil {
		t.Fatal(err)
	}

	chunkCollection, _ := app.FindCollectionByNameOrId("flow_activity_chunks")
	chunk := core.NewRecord(chunkCollection)
	chunk.Set("session", session.Id)
	chunk.Set("flow", flowIDs[0])
	chunk.Set("chunk_key", "large-timeline-chunk")
	chunk.Set("flow_key", "large-timeline-flow")
	chunk.Set("chunk_start", start.Format(time.RFC3339Nano))
	chunk.Set("bucket_ms", 50)
	chunk.Set("chunk_ms", 5000)
	chunk.Set("samples", map[string]any{
		"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
		"samples": [][]int64{{0, 10, 20, 1, 2}},
	})
	if err := app.Save(chunk); err != nil {
		t.Fatal(err)
	}

	window, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from":  {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":    {strconv.FormatInt(start.Add(time.Hour).UnixMilli(), 10)},
		"lod":   {"overview"},
		"limit": {"250"},
	})
	if err != nil || status != 200 {
		t.Fatalf("large window failed: status=%d err=%v", status, err)
	}
	if len(window.Flows) != len(flowIDs) || len(window.Attributions) != 1 || len(window.FlowAssociations) != 1 || len(window.Destinations) != 1 || len(window.Routes) != 1 {
		t.Fatalf(
			"unexpected large window counts: flows=%d attributions=%d associations=%d destinations=%d routes=%d",
			len(window.Flows), len(window.Attributions), len(window.FlowAssociations), len(window.Destinations), len(window.Routes),
		)
	}

	filtered, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from":  {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":    {strconv.FormatInt(start.Add(5*time.Minute).UnixMilli(), 10)},
		"lod":   {"50ms"},
		"limit": {"250"},
		"flow":  {strings.Join(flowIDs[:maxTimelineFlowFilter], ",")},
	})
	if err != nil || status != 200 {
		t.Fatalf("large filtered window failed: status=%d err=%v", status, err)
	}
	if len(filtered.Flows) != maxTimelineFlowFilter || len(filtered.FlowActivityChunks) != 1 {
		t.Fatalf("unexpected filtered counts: flows=%d chunks=%d", len(filtered.Flows), len(filtered.FlowActivityChunks))
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
	session.Set("gate_audit_complete", false)
	session.Set("gate_audit_drops", 2)
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

	gateCollection, _ := app.FindCollectionByNameOrId("gate_events")
	gate := core.NewRecord(gateCollection)
	gate.Set("session", session.Id)
	gate.Set("decision_id", "timeline-decision")
	gate.Set("flow_key", flow.GetString("flow_key"))
	gate.Set("client_ip", "10.0.0.50")
	gate.Set("destination_ip", "93.184.216.34")
	gate.Set("source_port", 53000)
	gate.Set("destination_port", 443)
	gate.Set("protocol", "tcp")
	gate.Set("packet_count", 1)
	gate.Set("state", "approved")
	gate.Set("verdict_source", "operator")
	gate.Set("queued_at", start.Add(1500*time.Millisecond).Format(time.RFC3339Nano))
	gate.Set("decided_at", start.Add(2*time.Second).Format(time.RFC3339Nano))
	gate.Set("wait_ms", 500)
	if err := app.Save(gate); err != nil {
		t.Fatal(err)
	}

	manifest, err := buildSessionTimelineManifest(app, session.Id, start.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SessionID != session.Id || manifest.Counts["flows"] != 1 || manifest.Counts["flow_activity_chunks"] != 1 || manifest.Counts["gate_events"] != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if manifest.GateAuditComplete || manifest.GateAuditDrops != 2 {
		t.Fatalf("gate audit disclosure missing: %#v", manifest)
	}

	window, status, err := buildSessionTimelineWindow(app, session.Id, map[string][]string{
		"from": {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":   {strconv.FormatInt(start.Add(10*time.Second).UnixMilli(), 10)},
		"lod":  {"500ms"},
	})
	if err != nil || status != 200 {
		t.Fatalf("window failed: status=%d err=%v", status, err)
	}
	if len(window.Flows) != 1 || len(window.FlowActivityChunks) != 1 || len(window.GateEvents) != 1 {
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
