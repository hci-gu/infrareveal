package main

import (
	"fmt"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"testing"
	"time"
)

func TestRouteHistoryPagesIndependentlyAndIncludesAnchor(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	defer app.ResetBootstrapState()
	create := func(name string, values map[string]any) *core.Record {
		c, _ := app.FindCollectionByNameOrId(name)
		r := core.NewRecord(c)
		for k, v := range values {
			r.Set(k, v)
		}
		if err := app.Save(r); err != nil {
			t.Fatal(err)
		}
		return r
	}
	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	session := create("sessions", map[string]any{"active": true, "started_at": start})
	create("flows", map[string]any{"session": session.Id, "flow_key": "test-flow", "client_ip": "10.0.0.50", "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "start": start, "last_seen": start.Add(time.Second)})
	for i := 0; i < 10; i++ {
		create("routes", map[string]any{"session": session.Id, "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "method": "tcp:443", "available_at": start.Add(time.Duration(i) * time.Second), "revision": i})
	}
	query := map[string][]string{"from": {fmt.Sprint(start.Add(3 * time.Second).UnixMilli())}, "to": {fmt.Sprint(start.Add(8 * time.Second).UnixMilli())}, "lod": {"50ms"}, "limit": {"2"}}
	var revisions []int
	for pages := 0; pages < 10; pages++ {
		window, status, err := buildSessionTimelineWindow(app, session.Id, query)
		if err != nil {
			t.Fatalf("status=%d %v", status, err)
		}
		for _, route := range window.Routes {
			revisions = append(revisions, int(route["revision"].(float64)))
		}
		if window.NextCursor == nil {
			break
		}
		query["cursor"] = []string{*window.NextCursor}
	}
	if fmt.Sprint(revisions) != "[2 3 4 5 6 7]" {
		t.Fatalf("lost anchor/history after flow page: %v", revisions)
	}
	routes, _, err := queryRouteRevisions(app, session.Id, start, start.Add(8*time.Second), nil, true, 10, 0)
	if err != nil || len(routes) != 1 || routes[0].GetInt("revision") != 7 {
		t.Fatalf("overview not bounded/latest: %v %v", routes, err)
	}
}
