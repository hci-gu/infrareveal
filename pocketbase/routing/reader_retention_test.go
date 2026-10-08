package routing

import (
	"errors"
	"fmt"
	"myapp/testsupport"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

func TestRouteReaderPreservesIndependentPaginationAndEvidenceTimes(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	flow := testsupport.Save(t, app, "flows", map[string]any{"session": session, "flow_key": "reader", "client_ip": "10.0.0.2", "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "start": start})
	routes := []*core.Record{}
	for i := range 10 {
		routes = append(routes, testsupport.Save(t, app, "routes", map[string]any{"session": session, "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "method": "tcp:443", "network_context": "n", "available_at": start.Add(time.Duration(i) * time.Second), "revision": i}))
	}
	query := RouteQuery{Session: session, From: start.Add(3 * time.Second), To: start.Add(8 * time.Second), FlowIDs: []string{flow.Id}, Limit: 2}
	var revisions []int
	for {
		page, err := QueryRoutes(app, query)
		if err != nil {
			t.Fatal(err)
		}
		for _, route := range page.Records {
			revisions = append(revisions, route.GetInt("revision"))
		}
		if !page.More {
			break
		}
		query.Offset += query.Limit
	}
	if fmt.Sprint(revisions) != "[2 3 4 5 6 7]" {
		t.Fatal("lost route anchor or independent history", revisions)
	}
	query.Offset, query.Overview = 0, true
	page, err := QueryRoutes(app, query)
	if err != nil || len(page.Records) != 1 || page.Records[0].GetInt("revision") != 7 {
		t.Fatalf("overview: %+v %v", page, err)
	}
	query.Offset = -1
	page, err = QueryRoutes(app, query)
	if err != nil || len(page.Records) != 0 || page.More {
		t.Fatal("completed cursor was restarted", page, err)
	}

	testsupport.Save(t, app, "route_evidence_updates", map[string]any{"key": "enriched", "session": session, "binding_key": routes[2].Id, "kind": "enriched", "available_at": start.Add(4 * time.Second), "value": map[string]any{"5": map[string]any{}}})
	testsupport.Save(t, app, "route_evidence_updates", map[string]any{"key": "network", "session": session, "network_context": "n", "kind": "network_invalidated", "available_at": start.Add(6 * time.Second)})
	before, err := ExportRoutes(app, routes[2:4], start.Add(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(before[0]["evidence_updates"].([]map[string]any)) != 1 || len(before[1]["evidence_updates"].([]map[string]any)) != 0 {
		t.Fatal("event escaped its route or availability", before)
	}
	after, err := ExportRoutes(app, []*core.Record{routes[2], routes[7]}, start.Add(8*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if len(after[0]["evidence_updates"].([]map[string]any)) != 2 || len(after[1]["evidence_updates"].([]map[string]any)) != 0 {
		t.Fatal("network epoch invalidated newer evidence", after)
	}
}

func TestRouteRetentionUsesCallerTransactionAndPreservesAnchors(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	testsupport.Save(t, app, "flows", map[string]any{"session": session, "flow_key": "retained", "client_ip": "10.0.0.2", "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "start": start})
	var routes []*core.Record
	for i := range 3 {
		routes = append(routes, testsupport.Save(t, app, "routes", map[string]any{"session": session, "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "method": "tcp:443", "available_at": start.Add(time.Duration(i) * time.Second)}))
	}
	for i := range 2 {
		testsupport.Save(t, app, "route_evidence_updates", map[string]any{"key": fmt.Sprint(i), "session": session, "binding_key": routes[1].Id, "kind": "confirmed", "available_at": start.Add(time.Second + time.Duration(i+1)*100*time.Millisecond)})
	}
	cutoff := start.Add(2 * time.Second)
	rollback := errors.New("later retention module failed")
	err := app.RunInTransaction(func(tx core.App) error {
		if err := RetainSession(tx, session, cutoff); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	remaining, _ := app.FindAllRecords("routes")
	events, _ := app.FindAllRecords("route_evidence_updates")
	if len(remaining) != 3 || len(events) != 2 {
		t.Fatal("route retention escaped caller rollback")
	}
	if err := app.RunInTransaction(func(tx core.App) error { return RetainSession(tx, session, cutoff) }); err != nil {
		t.Fatal(err)
	}
	remaining, _ = app.FindAllRecords("routes")
	events, _ = app.FindAllRecords("route_evidence_updates")
	if len(remaining) != 2 || len(events) != 1 || events[0].GetString("key") != "1" {
		t.Fatal("route/event anchors were lost", remaining, events)
	}
	if _, err := app.FindRecordById("routes", routes[1].Id); err != nil {
		t.Fatal("last pre-window route removed", err)
	}
}

func TestSharedRetentionKeepsRecordingEvidenceAndIndependentCutoffs(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	now := time.Now()
	old := now.Add(-2 * time.Hour)
	retained := testsupport.Save(t, app, "route_observations", map[string]any{"cache_key": "retained", "attempt_id": "retained", "revision": 1, "measured_at": old})
	orphan := testsupport.Save(t, app, "route_observations", map[string]any{"cache_key": "orphan", "attempt_id": "orphan", "revision": 1, "measured_at": old})
	testsupport.Save(t, app, "routes", map[string]any{"session": session, "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "method": "tcp:443", "observation_id": retained.Id})
	if err := saveCache(app, "still-recent", cacheEntry{}, old); err != nil {
		t.Fatal(err)
	}
	if err := saveCache(app, "expired", cacheEntry{}, now.Add(-25*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := RetainShared(app, now.Add(-time.Hour), now.Add(-24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, err := app.FindRecordById("route_observations", retained.Id); err != nil {
		t.Fatal("recording evidence expired", err)
	}
	if _, err := app.FindRecordById("route_observations", orphan.Id); err == nil {
		t.Fatal("unreferenced observation survived")
	}
	cache, err := app.FindAllRecords("route_cache")
	if err != nil || len(cache) != 1 || cache[0].GetString("cache_key") != "still-recent" {
		t.Fatal("session cutoff changed global cache lifetime", cache, err)
	}
}
