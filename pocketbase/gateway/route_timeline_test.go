package gateway

import (
	"fmt"
	"myapp/routing"
	"myapp/testsupport"
	"testing"
	"time"
)

func TestRouteHistoryPagesIndependentlyAndIncludesAnchor(t *testing.T) {
	app := testsupport.App(t)

	start := time.Date(2026, 9, 10, 12, 0, 0, 0, time.UTC)
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "started_at": start})
	testsupport.Save(t, app, "flows", map[string]any{"session": session.Id, "flow_key": "test-flow", "client_ip": "10.0.0.50", "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "start": start, "last_seen": start.Add(time.Second)})
	for i := 0; i < 10; i++ {
		testsupport.Save(t, app, "routes", map[string]any{"session": session.Id, "destination_ip": "9.9.9.9", "destination_port": 443, "protocol": "tcp", "method": "tcp:443", "available_at": start.Add(time.Duration(i) * time.Second), "revision": i})
	}
	query := map[string][]string{"from": {fmt.Sprint(start.Add(3 * time.Second).UnixMilli())}, "to": {fmt.Sprint(start.Add(8 * time.Second).UnixMilli())}, "lod": {"50ms"}, "limit": {"2"}}
	var revisions []int
	for pages := 0; pages < 10; pages++ {
		window, status, err := readTimelineWindow(app, session.Id, query)
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
	page, err := routing.QueryRoutes(app, routing.RouteQuery{Session: session.Id, From: start, To: start.Add(8 * time.Second), Overview: true, Limit: 10})
	routes := page.Records
	if err != nil || len(routes) != 1 || routes[0].GetInt("revision") != 7 {
		t.Fatalf("overview not bounded/latest: %v %v", routes, err)
	}
}
