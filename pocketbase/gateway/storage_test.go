package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/testsupport"
)

func TestStorageReportsFilesystemAndIndexedSessionCounts(t *testing.T) {
	app, _, handler := gatewayHTTP(t)
	s := testsupport.Save(t, app, "sessions", map[string]any{"name": "stored", "started_ms": 1000})
	testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": s.Id, "start_ms": 1000, "samples": []data.Sample{{0, 5, 0, 0, 0, 1, 0}}})
	response := requestJSON(t, handler, http.MethodGet, "/api/infrareveal/storage", "", "")
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body.String())
	}
	var result struct {
		Disk      filesystemUsage `json:"disk"`
		Databases []databaseUsage `json:"databases"`
		Counts    []struct {
			Session string `json:"session"`
			Chunks  int    `json:"chunks"`
		} `json:"session_counts"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if result.Disk.Total == 0 || result.Disk.Available > result.Disk.Total || len(result.Databases) != 2 || len(result.Counts) != 1 || result.Counts[0].Chunks != 1 || result.Counts[0].Session != s.Id {
		t.Fatalf("storage: %+v", result)
	}
}
func TestDeleteLiveSessionCascadesAndReplacesAtomically(t *testing.T) {
	for _, demo := range []bool{false, true} {
		t.Run(map[bool]string{false: "recording", true: "demo"}[demo], func(t *testing.T) {
			app, g, handler := gatewayHTTP(t)
			g.config.Demo = demo
			if err := data.InstallDiagnostics(app); err != nil {
				t.Fatal(err)
			}
			s := testsupport.Save(t, app, "sessions", map[string]any{"name": "delete me", "active": true, "ephemeral": true, "demo": demo, "retention_minutes": 30})
			other := testsupport.Save(t, app, "sessions", map[string]any{"name": "keep me"})
			shared := testsupport.Save(t, app, "destinations", map[string]any{"ip": "1.1.1.1"})
			exclusive := testsupport.Save(t, app, "destinations", map[string]any{"ip": "8.8.8.8"})
			for _, pair := range [][2]string{{s.Id, exclusive.Id}, {s.Id, shared.Id}, {other.Id, shared.Id}} {
				testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": pair[0], "destination_id": pair[1], "start_ms": time.Now().UnixMilli(), "samples": []data.Sample{{0, 1, 0, 0, 0, 1, 0}}})
			}
			for _, table := range []string{"activity_blocks", "capture_intervals", "route_evidence", "flow_diagnostics", "dns_queries", "gate_events"} {
				testsupport.Save(t, app, table, map[string]any{"session": s.Id, "kind": "path"})
			}
			admission := testsupport.Save(t, app, "probe_runs", map[string]any{"session": s.Id, "admitted_ms": time.Now().UnixMilli()})
			failure := app.OnRecordCreateExecute("sessions").BindFunc(func(e *core.RecordEvent) error { return errors.New("fixture failure") })
			response := requestJSON(t, handler, http.MethodDelete, "/api/infrareveal/sessions/"+s.Id, "", "")
			if response.Code < 400 {
				t.Fatal("replacement failure accepted")
			}
			if _, err := app.FindRecordById("sessions", s.Id); err != nil || g.CurrentSessionID() != s.Id {
				t.Fatal("failed delete changed current session", err)
			}
			if n, _ := app.CountRecords("traffic_chunks"); n != 3 {
				t.Fatal("failed delete lost traffic", n)
			}
			app.OnRecordCreateExecute("sessions").Unbind(failure)
			response = requestJSON(t, handler, http.MethodDelete, "/api/infrareveal/sessions/"+s.Id, "", "")
			if response.Code != 204 {
				t.Fatal(response.Code, response.Body.String())
			}
			if _, err := app.FindRecordById("sessions", s.Id); err == nil {
				t.Fatal("deleted session remains")
			}
			fresh, err := app.FindRecordById("sessions", g.CurrentSessionID())
			if err != nil || fresh.Id == s.Id || !fresh.GetBool("active") || fresh.GetInt("retention_minutes") != 30 {
				t.Fatal("replacement session", err)
			}
			for _, table := range []string{"activity_blocks", "capture_intervals", "route_evidence", "flow_diagnostics", "dns_queries", "gate_events"} {
				if n, _ := app.CountRecords(table); n != 0 {
					t.Fatal("underlying data remains", table, n)
				}
			}
			if n, _ := app.CountRecords("traffic_chunks"); n != 1 {
				t.Fatal("unrelated traffic changed", n)
			}
			if _, err := app.FindRecordById("destinations", exclusive.Id); err == nil {
				t.Fatal("orphan destination retained")
			}
			if _, err := app.FindRecordById("destinations", shared.Id); err != nil {
				t.Fatal("shared destination deleted")
			}
			if _, err := app.FindRecordById("probe_runs", admission.Id); err != nil {
				t.Fatal("network quota was refunded")
			}
		})
	}
}
