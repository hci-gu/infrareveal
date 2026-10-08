package gateway

import (
	"encoding/json"
	"fmt"
	"github.com/pocketbase/pocketbase/core"
	"myapp/timeline"
	"os"
	"reflect"
	"testing"
	"time"
)

// The same fixture is consumed by both TypeScript transports. Persist its raw
// records and compare real Go reader output, allowing storage's extra fields and
// PocketBase's equivalent timestamp representation.
func TestSharedTimelineWireContract(t *testing.T) {
	raw, err := os.ReadFile("../../testdata/session-timeline-contract-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Session  map[string]any `json:"session"`
		Manifest map[string]any `json:"manifest"`
		Window   map[string]any `json:"window"`
	}
	if err = json.Unmarshal(raw, &fixture); err != nil {
		t.Fatal(err)
	}
	app := ephemeralTestApp(t)
	save := func(collection string, values map[string]any) {
		c, err := app.FindCollectionByNameOrId(collection)
		if err != nil {
			t.Fatal(err)
		}
		record := core.NewRecord(c)
		for key, value := range values {
			record.Set(key, value)
		}

		if err = app.Save(record); err != nil {
			t.Fatalf("%s: %v", collection, err)
		}
	}
	save("sessions", fixture.Session)
	for _, entry := range [][2]string{{"flows", "flows"}, {"dnsQueries", "dns_queries"}, {"attributions", "flow_attributions"}, {"activityEpisodes", "activity_episodes"}, {"flowAssociations", "flow_associations"}, {"flowActivityChunks", "flow_activity_chunks"}, {"flowActivityWindows", "flow_activity_windows"}, {"flowActivityStatuses", "flow_activity_status"}, {"destinations", "destinations"}, {"routes", "routes"}, {"gateEvents", "gate_events"}} {
		for _, value := range fixture.Window[entry[0]].([]any) {
			save(entry[1], value.(map[string]any))
		}
	}
	for _, rawRoute := range fixture.Window["routes"].([]any) {
		route := rawRoute.(map[string]any)
		for _, rawUpdate := range route["evidence_updates"].([]any) {
			update := rawUpdate.(map[string]any)
			values := map[string]any{"session": fixture.Session["id"], "binding_key": route["id"], "network_context": route["network_context"], "key": fmt.Sprint(route["id"], "|", update["kind"], "|", update["available_at"])}
			for key, value := range update {
				values[key] = value
			}
			save("route_evidence_updates", values)
		}
	}
	id := fixture.Session["id"].(string)
	now, err := time.Parse(time.RFC3339Nano, fixture.Manifest["serverNow"].(string))
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := timeline.New(app).Manifest(id, now)
	if err != nil {
		t.Fatal(err)
	}
	checkContract(t, "manifest", fixture.Manifest, jsonObject(t, manifest))
	rangeValue := fixture.Window["range"].(map[string]any)
	window, status, err := readTimelineWindow(app, id, map[string][]string{"from": {rangeValue["from"].(string)}, "to": {rangeValue["to"].(string)}, "lod": {fixture.Window["lod"].(string)}})
	if err != nil || status != 200 {
		t.Fatalf("%d %v", status, err)
	}
	actual := jsonObject(t, window)
	delete(fixture.Window, "watermark") // generated at request time
	checkContract(t, "window", fixture.Window, actual)
}

func jsonObject(t *testing.T, value any) map[string]any {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	var result map[string]any
	if err = json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}
func checkContract(t *testing.T, path string, want, got any) {
	t.Helper()
	switch expected := want.(type) {
	case map[string]any:
		actual, ok := got.(map[string]any)
		if !ok {
			t.Fatalf("%s: expected object, got %T", path, got)
		}
		for key, value := range expected {
			if key == "created" || key == "updated" {
				continue
			}
			checkContract(t, path+"."+key, value, actual[key])
		}
	case []any:
		actual, ok := got.([]any)
		if !ok || len(actual) != len(expected) {
			t.Fatalf("%s: expected %d entries, got %#v", path, len(expected), got)
		}
		for i, value := range expected {
			checkContract(t, fmt.Sprintf("%s[%d]", path, i), value, actual[i])
		}
	default:
		normalize := func(v any) any {
			if text, ok := v.(string); ok {
				for _, layout := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.000Z"} {
					if at, err := time.Parse(layout, text); err == nil {
						return at.UnixMilli()
					}
				}
			}
			return v
		}
		if !reflect.DeepEqual(normalize(want), normalize(got)) {
			t.Fatalf("%s: want %#v, got %#v", path, want, got)
		}
	}
}
