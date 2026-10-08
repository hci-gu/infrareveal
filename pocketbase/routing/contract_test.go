package routing

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

// This fixture is also consumed by the TypeScript route readers. Persist both
// wire generations through the actual schema before testing their read contract.
func TestSharedRouteEvidenceContract(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/route-evidence-contract-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Route, LegacyRoute    map[string]any
		Updates               []map[string]any
		ExpectedAttachedKinds []string
		Cursors               map[string]string
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	app := testApp(t)
	session := fixture.Route["session"].(string)
	sessions := map[string]bool{session: true}
	for _, update := range fixture.Updates {
		sessions[update["session"].(string)] = true
	}
	for id := range sessions {
		saveRoutingRecord(t, app, "sessions", map[string]any{"id": id, "active": false})
	}
	saveRoutingRecord(t, app, "destinations", map[string]any{"id": fixture.Route["destination"], "ip": fixture.Route["destination_ip"]})
	legacy := saveRoutingRecord(t, app, "routes", fixture.LegacyRoute)
	current := saveRoutingRecord(t, app, "routes", fixture.Route)
	byID := map[string]map[string]any{}
	for _, update := range fixture.Updates {
		saveRoutingRecord(t, app, "route_evidence_updates", update)
		byID[update["id"].(string)] = update
	}

	for _, test := range []struct {
		cursor          string
		current, legacy []string
	}{
		{"beforeConfirmation", nil, []string{"beforefixture01"}},
		{"afterConfirmation", []string{"confirmfixture1"}, []string{"beforefixture01"}},
		{"afterEnrichment", []string{"confirmfixture1", "enrichfixture01"}, []string{"beforefixture01"}},
		{"afterInvalidation", []string{"confirmfixture1", "enrichfixture01", "invalidate00001"}, []string{"beforefixture01", "invalidate00001"}},
	} {
		t.Run(test.cursor, func(t *testing.T) {
			rows, err := ExportRoutes(app, []*core.Record{current, legacy}, routeFixtureTime(t, fixture.Cursors[test.cursor]))
			if err != nil || len(rows) != 2 {
				t.Fatalf("export: %v %v", rows, err)
			}
			for index, expected := range []map[string]any{fixture.Route, fixture.LegacyRoute} {
				for field, value := range expected {
					assertRouteJSON(t, field, value, rows[index][field])
				}
			}
			for index, ids := range [][]string{test.current, test.legacy} {
				updates := rows[index]["evidence_updates"].([]map[string]any)
				if len(updates) != len(ids) {
					t.Fatalf("route %v: expected updates %v, got %v", rows[index]["id"], ids, updates)
				}
				kinds := []string{}
				for i, id := range ids {
					want := byID[id]
					assertRouteJSON(t, "kind", want["kind"], updates[i]["kind"])
					assertRouteJSON(t, "value", want["value"], updates[i]["value"])
					if !routeFixtureTime(t, want["available_at"].(string)).Equal(routeFixtureTime(t, updates[i]["available_at"].(string))) {
						t.Fatal("event availability changed", updates[i])
					}
					kinds = append(kinds, updates[i]["kind"].(string))
				}
				if index == 0 && test.cursor == "afterInvalidation" && !reflect.DeepEqual(kinds, fixture.ExpectedAttachedKinds) {
					t.Fatalf("attached kinds: %v", kinds)
				}
			}
		})
	}

	// The flow has already fallen outside the requested window. Its route
	// history still has its own cursor, including the legacy pre-window anchor.
	start := routeFixtureTime(t, fixture.Route["measured_at"].(string))
	flow := saveRoutingRecord(t, app, "flows", map[string]any{"session": session, "flow_key": "route-contract", "client_ip": "10.0.0.2", "destination_ip": fixture.Route["destination_ip"], "destination_port": fixture.Route["destination_port"], "protocol": fixture.Route["protocol"], "start": start, "last_seen": start})
	query := RouteQuery{Session: session, From: routeFixtureTime(t, "2026-09-10T12:00:00.750Z"), To: routeFixtureTime(t, fixture.Cursors["afterInvalidation"]), FlowIDs: []string{flow.Id}, Limit: 1}
	for index, want := range []*core.Record{legacy, current} {
		query.Offset = index
		page, err := QueryRoutes(app, query)
		if err != nil || len(page.Records) != 1 || page.Records[0].Id != want.Id || page.More != (index == 0) {
			t.Fatalf("route page %d: %+v %v", index, page, err)
		}
	}
	query.Offset = -1
	page, err := QueryRoutes(app, query)
	if err != nil || len(page.Records) != 0 || page.More {
		t.Fatalf("completed route cursor restarted: %+v %v", page, err)
	}
	query.Offset, query.Overview = 0, true
	page, err = QueryRoutes(app, query)
	if err != nil || len(page.Records) != 1 || page.Records[0].Id != current.Id || page.More {
		t.Fatalf("overview did not select latest route: %+v %v", page, err)
	}
}

func assertRouteJSON(t *testing.T, field string, want, got any) {
	t.Helper()
	wantJSON, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}
	gotJSON, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if string(wantJSON) != string(gotJSON) {
		t.Fatalf("%s: want %s, got %s", field, wantJSON, gotJSON)
	}
}

func routeFixtureTime(t *testing.T, value string) time.Time {
	t.Helper()
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.000Z"} {
		if at, err := time.Parse(layout, value); err == nil {
			return at
		}
	}
	t.Fatalf("invalid fixture time %q", value)
	return time.Time{}
}
