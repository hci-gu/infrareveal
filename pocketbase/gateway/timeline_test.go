package gateway

import (
	"fmt"
	"myapp/testsupport"
	"strconv"
	"strings"
	"testing"
	"time"

	"myapp/timeline"
)

func TestSessionTimelineWindowSupportsMoreThanFilterExpressionLimit(t *testing.T) {
	app := testsupport.App(t)

	start := time.Date(2026, 9, 3, 9, 0, 0, 0, time.UTC)
	session := testsupport.Save(t, app, "sessions", map[string]any{
		"name":       "Large timeline test",
		"active":     true,
		"started_at": start.Format(time.RFC3339Nano),
	})

	flowIDs := make([]string, 0, 205)
	for index := 0; index < 205; index++ {
		flow := testsupport.Save(t, app, "flows", map[string]any{
			"session":          session.Id,
			"flow_key":         fmt.Sprintf("tcp|10.0.0.50|%d|198.51.%d.%d|443", 40000+index, index/250, index%250+1),
			"client_ip":        "10.0.0.50",
			"destination_ip":   fmt.Sprintf("198.51.%d.%d", index/250, index%250+1),
			"source_port":      40000 + index,
			"destination_port": 443,
			"protocol":         "tcp",
			"start":            start.Add(time.Duration(index) * time.Millisecond).Format(time.RFC3339Nano),
			"last_seen":        start.Add(time.Minute).Format(time.RFC3339Nano),
		})
		flowIDs = append(flowIDs, flow.Id)
	}

	testsupport.Save(t, app, "flow_attributions", map[string]any{
		"session":            session.Id,
		"flow":               flowIDs[0],
		"candidate_hostname": "example.test",
		"source_signal":      "dns",
		"confidence":         "high",
		"observed_at":        start.Format(time.RFC3339Nano),
	})

	episode := testsupport.Save(t, app, "activity_episodes", map[string]any{
		"session":         session.Id,
		"episode_key":     "large-timeline-episode",
		"client_ip":       "10.0.0.50",
		"site_key":        "example.test",
		"label":           "Example",
		"anchor_hostname": "example.test",
		"start":           start.Format(time.RFC3339Nano),
		"last_seen":       start.Add(time.Minute).Format(time.RFC3339Nano),
		"confidence":      "high",
	})

	testsupport.Save(t, app, "flow_associations", map[string]any{
		"session":         session.Id,
		"flow":            flowIDs[0],
		"episode":         episode.Id,
		"parent_site_key": "example.test",
		"parent_label":    "Example",
		"relationship":    "first_party",
		"confidence":      "high",
		"score":           100,
		"observed_at":     start.Format(time.RFC3339Nano),
	})

	destination := testsupport.Save(t, app, "destinations", map[string]any{
		"ip":          "198.51.0.1",
		"reverse_dns": "example.test",
		"first_seen":  start.Format(time.RFC3339Nano),
		"last_seen":   start.Add(time.Minute).Format(time.RFC3339Nano),
	})

	testsupport.Save(t, app, "routes", map[string]any{
		"session":          session.Id,
		"destination":      destination.Id,
		"destination_ip":   destination.GetString("ip"),
		"destination_port": 443,
		"protocol":         "tcp",
		"method":           "traceroute",
		"started_at":       start.Format(time.RFC3339Nano),
		"completed_at":     start.Add(time.Second).Format(time.RFC3339Nano),
	})

	testsupport.Save(t, app, "flow_activity_chunks", map[string]any{
		"session":     session.Id,
		"flow":        flowIDs[0],
		"chunk_key":   "large-timeline-chunk",
		"flow_key":    "large-timeline-flow",
		"chunk_start": start.Format(time.RFC3339Nano),
		"bucket_ms":   50,
		"chunk_ms":    5000,
		"samples": map[string]any{
			"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
			"samples": [][]int64{{0, 10, 20, 1, 2}},
		},
	})

	window, status, err := readTimelineWindow(app, session.Id, map[string][]string{
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

	filtered, status, err := readTimelineWindow(app, session.Id, map[string][]string{
		"from":  {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":    {strconv.FormatInt(start.Add(5*time.Minute).UnixMilli(), 10)},
		"lod":   {"50ms"},
		"limit": {"250"},
		"flow":  {strings.Join(flowIDs[:200], ",")},
	})
	if err != nil || status != 200 {
		t.Fatalf("large filtered window failed: status=%d err=%v", status, err)
	}
	if len(filtered.Flows) != 200 || len(filtered.FlowActivityChunks) != 1 {
		t.Fatalf("unexpected filtered counts: flows=%d chunks=%d", len(filtered.Flows), len(filtered.FlowActivityChunks))
	}
}

func TestSessionTimelineManifestAndWindow(t *testing.T) {
	app := testsupport.App(t)

	start := time.Date(2026, 9, 2, 9, 0, 0, 0, time.UTC)
	session := testsupport.Save(t, app, "sessions", map[string]any{
		"name":                "Timeline test",
		"active":              true,
		"started_at":          start.Format(time.RFC3339Nano),
		"gate_audit_complete": false,
		"gate_audit_drops":    2,
	})
	if session.GetDateTime("created").IsZero() || session.GetDateTime("updated").IsZero() {
		t.Fatalf("session revision fields were not populated: created=%q updated=%q", session.GetString("created"), session.GetString("updated"))
	}

	flow := testsupport.Save(t, app, "flows", map[string]any{
		"session":          session.Id,
		"flow_key":         "tcp|10.0.0.50|53000|93.184.216.34|443",
		"client_ip":        "10.0.0.50",
		"destination_ip":   "93.184.216.34",
		"source_port":      53000,
		"destination_port": 443,
		"protocol":         "tcp",
		"start":            start.Add(time.Second).Format(time.RFC3339Nano),
		"last_seen":        start.Add(4 * time.Second).Format(time.RFC3339Nano),
	})
	if flow.GetDateTime("created").IsZero() || flow.GetDateTime("updated").IsZero() {
		t.Fatalf("flow revision fields were not populated: created=%q updated=%q", flow.GetString("created"), flow.GetString("updated"))
	}

	testsupport.Save(t, app, "flow_activity_chunks", map[string]any{
		"session":     session.Id,
		"flow":        flow.Id,
		"chunk_key":   "timeline-test",
		"flow_key":    flow.GetString("flow_key"),
		"chunk_start": start.Format(time.RFC3339Nano),
		"bucket_ms":   50,
		"chunk_ms":    5000,
		"samples": map[string]any{
			"version": 1, "bucket_ms": 50, "chunk_ms": 5000,
			"samples": [][]int64{{1000, 10, 20, 1, 2}, {1050, 5, 5, 1, 1}},
		},
	})

	testsupport.Save(t, app, "gate_events", map[string]any{
		"session":          session.Id,
		"decision_id":      "timeline-decision",
		"flow_key":         flow.GetString("flow_key"),
		"client_ip":        "10.0.0.50",
		"destination_ip":   "93.184.216.34",
		"source_port":      53000,
		"destination_port": 443,
		"protocol":         "tcp",
		"packet_count":     1,
		"state":            "approved",
		"verdict_source":   "operator",
		"queued_at":        start.Add(1500 * time.Millisecond).Format(time.RFC3339Nano),
		"decided_at":       start.Add(2 * time.Second).Format(time.RFC3339Nano),
		"wait_ms":          500,
	})

	manifest, err := timeline.New(app).Manifest(session.Id, start.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.SessionID != session.Id || manifest.Counts["flows"] != 1 || manifest.Counts["flow_activity_chunks"] != 1 || manifest.Counts["gate_events"] != 1 {
		t.Fatalf("unexpected manifest: %#v", manifest)
	}
	if manifest.GateAuditComplete || manifest.GateAuditDrops != 2 {
		t.Fatalf("gate audit disclosure missing: %#v", manifest)
	}

	window, status, err := readTimelineWindow(app, session.Id, map[string][]string{
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

	testsupport.Save(t, app, "flows", map[string]any{
		"session":          session.Id,
		"flow_key":         "tcp|10.0.0.51|53001|1.1.1.1|443",
		"client_ip":        "10.0.0.51",
		"destination_ip":   "1.1.1.1",
		"source_port":      53001,
		"destination_port": 443,
		"protocol":         "tcp",
		"start":            start.Add(2 * time.Second).Format(time.RFC3339Nano),
		"last_seen":        start.Add(5 * time.Second).Format(time.RFC3339Nano),
	})

	filtered, status, err := readTimelineWindow(app, session.Id, map[string][]string{
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

	overview, status, err := readTimelineWindow(app, session.Id, map[string][]string{
		"from": {strconv.FormatInt(start.UnixMilli(), 10)},
		"to":   {strconv.FormatInt(start.Add(time.Hour).UnixMilli(), 10)},
		"lod":  {"overview"},
	})
	if err != nil || status != 200 || len(overview.FlowActivityChunks) != 0 {
		t.Fatalf("overview should omit raw activity: status=%d err=%v chunks=%d", status, err, len(overview.FlowActivityChunks))
	}
}
