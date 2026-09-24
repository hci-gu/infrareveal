package main

import (
	"fmt"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

func ephemeralTestApp(t *testing.T) *pocketbase.PocketBase {
	t.Helper()
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	return app
}
func saveEphemeralFixture(t *testing.T, app core.App, name string, values map[string]any) *core.Record {
	t.Helper()
	c, err := app.FindCollectionByNameOrId(name)
	if err != nil {
		t.Fatal(err)
	}
	r := core.NewRecord(c)
	for key, value := range values {
		r.Set(key, value)
	}
	if err := app.Save(r); err != nil {
		t.Fatalf("save %s: %v", name, err)
	}
	return r
}

func TestEphemeralRetentionKeepsLiveFlowsAndOrdinaryHistory(t *testing.T) {
	app := ephemeralTestApp(t)
	now := time.Date(2026, 9, 17, 12, 0, 0, 0, time.UTC)
	old := now.Add(-24 * time.Hour)
	ephemeral := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": "Rolling", "ephemeral": true, "active": true, "started_at": old})
	normal := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": "Recorded", "active": false, "started_at": old, "ended_at": old.Add(time.Hour)})
	flow := func(session string, key string, last time.Time) *core.Record {
		return saveEphemeralFixture(t, app, "flows", map[string]any{"session": session, "flow_key": key, "protocol": "tcp", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "start": old, "last_seen": last})
	}
	stale := flow(ephemeral.Id, "stale", old)
	live := flow(ephemeral.Id, "live", now)
	historical := flow(normal.Id, "recorded", old)
	oldDNS := saveEphemeralFixture(t, app, "dns_queries", map[string]any{"session": ephemeral.Id, "query_name": "expired.test", "timestamp": old})
	anchorDNS := saveEphemeralFixture(t, app, "dns_queries", map[string]any{"session": ephemeral.Id, "query_name": "live.test", "timestamp": old})
	saveEphemeralFixture(t, app, "flow_attributions", map[string]any{"session": ephemeral.Id, "flow": live.Id, "dns_query": anchorDNS.Id, "source_signal": "dns", "candidate_hostname": "live.test", "confidence": "high", "observed_at": old})
	oldChunk := saveEphemeralFixture(t, app, "flow_activity_chunks", map[string]any{"session": ephemeral.Id, "flow": live.Id, "flow_key": "live", "chunk_key": "old", "chunk_start": old, "chunk_ms": 5000, "bucket_ms": 50, "samples": map[string]any{"buckets": []any{}}})
	recentChunk := saveEphemeralFixture(t, app, "flow_activity_chunks", map[string]any{"session": ephemeral.Id, "flow": live.Id, "flow_key": "live", "chunk_key": "new", "chunk_start": now.Add(-time.Second), "chunk_ms": 5000, "bucket_ms": 50, "samples": map[string]any{"buckets": []any{}}})
	route := func(ip string, at time.Time) *core.Record {
		return saveEphemeralFixture(t, app, "routes", map[string]any{"session": ephemeral.Id, "destination_ip": ip, "protocol": "tcp", "method": "traceroute", "available_at": at, "completed_at": at})
	}
	oldRoute := route("1.1.1.1", old)
	anchorRoute := route("1.1.1.1", old.Add(time.Minute))
	unusedRoute := route("8.8.8.8", old)
	oldEvent := saveEphemeralFixture(t, app, "route_evidence_updates", map[string]any{"key": "old", "session": ephemeral.Id, "binding_key": anchorRoute.Id, "kind": "validity", "available_at": old})
	anchorEvent := saveEphemeralFixture(t, app, "route_evidence_updates", map[string]any{"key": "anchor", "session": ephemeral.Id, "binding_key": anchorRoute.Id, "kind": "validity", "available_at": old.Add(time.Minute)})

	if err := pruneEphemeralSessions(app, now); err != nil {
		t.Fatal(err)
	}
	for collection, ids := range map[string][]string{"flows": {stale.Id}, "dns_queries": {oldDNS.Id}, "flow_activity_chunks": {oldChunk.Id}, "routes": {oldRoute.Id, unusedRoute.Id}, "route_evidence_updates": {oldEvent.Id}} {
		for _, id := range ids {
			if _, err := app.FindRecordById(collection, id); err == nil {
				t.Fatalf("expired %s/%s retained", collection, id)
			}
		}
	}
	for collection, ids := range map[string][]string{"flows": {live.Id, historical.Id}, "dns_queries": {anchorDNS.Id}, "flow_activity_chunks": {recentChunk.Id}, "routes": {anchorRoute.Id}, "route_evidence_updates": {anchorEvent.Id}} {
		for _, id := range ids {
			if _, err := app.FindRecordById(collection, id); err != nil {
				t.Fatalf("needed %s/%s removed: %v", collection, id, err)
			}
		}
	}
	manifest, err := buildSessionTimelineManifest(app, ephemeral.Id, now)
	if err != nil {
		t.Fatal(err)
	}
	if !manifest.Active || !manifest.Ephemeral || manifest.StartedAt != now.Add(-5*time.Minute).Format(time.RFC3339Nano) || manifest.Coverage.From != manifest.StartedAt || manifest.EndedAt != nil {
		t.Fatalf("bad rolling manifest: %+v", manifest)
	}
	record, _ := app.FindRecordById("sessions", ephemeral.Id)
	record.Set("active", false)
	record.Set("ended_at", now)
	normalizeEphemeralSession(record, now)
	if !record.GetBool("active") || !record.GetDateTime("ended_at").IsZero() {
		t.Fatal("ephemeral session was allowed to close")
	}
	record.Set("ephemeral", false)
	record.Set("active", false)
	normalizeEphemeralSession(record, now)
	if record.GetBool("active") {
		t.Fatal("normal session forced active")
	}
}

func TestEphemeralRetentionPlateausDuringLongOperation(t *testing.T) {
	app := ephemeralTestApp(t)
	start := time.Date(2026, 9, 17, 0, 0, 0, 0, time.UTC)
	session := saveEphemeralFixture(t, app, "sessions", map[string]any{"ephemeral": true, "active": true, "started_at": start})
	for minute := 0; minute < 180; minute++ {
		now := start.Add(time.Duration(minute) * time.Minute)
		saveEphemeralFixture(t, app, "flows", map[string]any{"session": session.Id, "flow_key": fmt.Sprint(minute), "protocol": "tcp", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "start": now, "last_seen": now})
		saveEphemeralFixture(t, app, "dns_queries", map[string]any{"session": session.Id, "query_name": "test.example", "timestamp": now})
		if err := pruneEphemeralSessions(app, now); err != nil {
			t.Fatal(err)
		}
		for _, name := range []string{"flows", "dns_queries"} {
			n, _ := app.CountRecords(name)
			if n > 6 {
				t.Fatalf("%s grew to %d after %d minutes", name, n, minute)
			}
		}
	}
}
