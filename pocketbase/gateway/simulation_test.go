package gateway

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"myapp/data"
	"myapp/testsupport"
)

func waitSimulation(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(6 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatal("simulation did not reach expected state")
}

func simulationCleanup(t *testing.T, g *Runtime) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
}

func assertSimulationGone(t *testing.T, app *pocketbase.PocketBase, id string) {
	t.Helper()
	if _, err := app.FindRecordById("sessions", id); err == nil {
		t.Fatal("simulation session remains")
	}
	for _, name := range []string{"traffic_chunks", "capture_intervals", "activity_blocks", "route_evidence", "dns_queries", "flow_diagnostics", "gate_events"} {
		if _, err := app.FindCollectionByNameOrId(name); err != nil {
			continue
		}
		count, err := app.CountRecords(name, dbx.HashExp{"session": id})
		if err != nil || count != 0 {
			t.Fatalf("%s leftovers: %d %v", name, count, err)
		}
	}
	count, err := app.CountRecords("destinations", dbx.HashExp{"version": "simulation-" + id})
	if err != nil || count != 0 {
		t.Fatalf("destination leftovers: %d %v", count, err)
	}
	if count, _ := app.CountRecords("probe_runs"); count != 0 {
		t.Fatal("simulation admitted network probes")
	}
}

func TestSimulationHTTPUsesRealPipelineAndPreservesRecording(t *testing.T) {
	app, g, handler := gatewayHTTP(t)
	g.config.Diagnostics = true
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	simulationCleanup(t, g)
	real := testsupport.Save(t, app, "sessions", map[string]any{"name": "real", "active": true})
	destination := testsupport.Save(t, app, "destinations", map[string]any{"ip": "192.0.2.1", "version": "real"})
	chunk := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": real.Id, "destination_id": destination.Id})
	response := requestJSON(t, handler, "POST", "/api/infrareveal/simulation", "", "")
	if response.Code != 201 {
		t.Fatalf("start: %d %s", response.Code, response.Body.String())
	}
	var run simulationStatus
	if err := json.Unmarshal(response.Body.Bytes(), &run); err != nil {
		t.Fatal(err)
	}
	if !run.Active || run.Lanes != 144 || run.ExpiresMS < time.Now().Add(179*time.Second).UnixMilli() || g.CurrentSessionID() != real.Id {
		t.Fatalf("invalid run: %+v", run)
	}
	repeated := requestJSON(t, handler, "POST", "/api/infrareveal/simulation", "", "")
	if repeated.Code != 200 || repeated.Body.String() != response.Body.String() {
		t.Fatal("POST duplicated or extended run")
	}
	waitSimulation(t, func() bool {
		count, _ := app.CountRecords("activity_blocks", dbx.HashExp{"session": run.SessionID})
		return count > 0
	})
	manifestResponse := requestJSON(t, handler, "GET", "/api/infrareveal/sessions/"+run.SessionID+"/manifest", "", "")
	var manifest data.Manifest
	if err := json.Unmarshal(manifestResponse.Body.Bytes(), &manifest); err != nil {
		t.Fatal(err)
	}
	if !manifest.Active || manifest.SimulationExpiresMS != run.ExpiresMS || !manifest.Capture.Running || manifest.Capture.Quality != "complete" || manifest.Capture.Dropped != 0 {
		t.Fatalf("bad capture: %+v", manifest)
	}
	mapResponse := requestJSON(t, handler, "GET", fmt.Sprintf("/api/infrareveal/sessions/%s/map?from=%d&to=%d&resolution=50", run.SessionID, manifest.StartedMS, time.Now().UnixMilli()), "", "")
	var window data.MapWindow
	if mapResponse.Code != 200 {
		t.Fatalf("map: %s", mapResponse.Body.String())
	}
	if err := json.Unmarshal(mapResponse.Body.Bytes(), &window); err != nil {
		t.Fatal(err)
	}
	var sent, received int64
	classified, mapped := false, false
	for _, series := range window.Series {
		classified = classified || series.ServiceLabel == "video-demo.test"
		for _, sample := range series.Samples {
			sent += sample[1]
			received += sample[2]
		}
	}
	for _, destination := range window.Destinations {
		mapped = mapped || destination.Lat != nil
	}
	if sent == 0 || received == 0 || !classified || !mapped || len(window.Coverage) == 0 {
		t.Fatalf("pipeline did not produce usable traffic: sent=%d received=%d DNS=%v mapped=%v", sent, received, classified, mapped)
	}
	if count, _ := app.CountRecords("dns_queries", dbx.HashExp{"session": run.SessionID}); count == 0 {
		t.Fatal("DNS did not traverse normal diagnostics")
	}
	// Starting another real recording must leave the synthetic run alive.
	next := requestJSON(t, handler, "POST", "/api/infrareveal/sessions", `{"name":"next real"}`, "")
	if next.Code != 201 {
		t.Fatalf("parallel capture: %s", next.Body.String())
	}
	current := g.CurrentSessionID()
	if current == run.SessionID || current == real.Id {
		t.Fatal("simulation changed real capture ownership")
	}
	if bad := requestJSON(t, handler, "DELETE", "/api/infrareveal/simulation?session_id=another", "", ""); bad.Code != 409 {
		t.Fatal("stale cancellation accepted")
	}
	if stop := requestJSON(t, handler, "DELETE", "/api/infrareveal/simulation?session_id="+run.SessionID, "", ""); stop.Code != 204 {
		t.Fatalf("stop: %s", stop.Body.String())
	}
	assertSimulationGone(t, app, run.SessionID)
	if g.CurrentSessionID() != current {
		t.Fatal("cleanup changed capture ownership")
	}
	for collection, id := range map[string]string{"sessions": real.Id, "destinations": destination.Id, "traffic_chunks": chunk.Id} {
		if _, err := app.FindRecordById(collection, id); err != nil {
			t.Fatalf("removed real %s: %v", collection, err)
		}
	}
	if stop := requestJSON(t, handler, http.MethodDelete, "/api/infrareveal/simulation", "", ""); stop.Code != 204 {
		t.Fatal("stop is not idempotent")
	}
}

func TestSimulationExpiryClearShutdownAndRecovery(t *testing.T) {
	for _, action := range []string{"expiry", "clear", "shutdown", "deleted", "ended", "cancelled-stop"} {
		t.Run(action, func(t *testing.T) {
			app, g, handler := gatewayHTTP(t)
			simulationCleanup(t, g)
			duration := time.Minute
			if action == "expiry" {
				duration = time.Second
			}
			g.operations.Lock()
			run, _, err := g.startSimulation(duration)
			g.operations.Unlock()
			if err != nil {
				t.Fatal(err)
			}
			waitSimulation(t, func() bool { count, _ := app.CountRecords("traffic_chunks"); return count > 0 })
			switch action {
			case "cancelled-stop":
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				g.operations.Lock()
				_ = g.stopSimulation(ctx)
				g.operations.Unlock()
			case "clear":
				_, err = g.Clear(context.Background())
			case "shutdown":
				err = g.Close(context.Background())
			case "deleted":
				response := requestJSON(t, handler, "DELETE", "/api/infrareveal/sessions/"+run.SessionID, "", "")
				if response.Code != 204 {
					t.Fatalf("delete: %s", response.Body.String())
				}
			case "ended":
				response := requestJSON(t, handler, "POST", "/api/infrareveal/sessions/"+run.SessionID+"/end", "", "")
				if response.Code != 200 {
					t.Fatalf("end: %s", response.Body.String())
				}
			}
			if err != nil {
				t.Fatal(err)
			}
			waitSimulation(t, func() bool { g.operations.Lock(); defer g.operations.Unlock(); return g.simulation == nil })
			assertSimulationGone(t, app, run.SessionID)
		})
	}
	t.Run("restart", func(t *testing.T) {
		app := testsupport.App(t)
		g := testRuntime(t, app)
		g.Register()
		g.config.Observation.Packet.Enabled = false
		g.config.Observation.DNSLogPath = ""
		simulationCleanup(t, g)
		orphan := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "simulation_expires_ms": time.Now().Add(time.Minute).UnixMilli()})
		testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": orphan.Id})
		if err := g.Start(); err != nil {
			t.Fatal(err)
		}
		assertSimulationGone(t, app, orphan.Id)
		if g.CurrentSessionID() == "" || g.CurrentSessionID() == orphan.Id {
			t.Fatal("restart did not restore real capture")
		}
	})
}

func TestSimulationCoexistsWithContinuousDemo(t *testing.T) {
	_, g, handler := gatewayHTTP(t)
	g.config.Demo = true
	simulationCleanup(t, g)
	if err := g.ensureDemoSession(); err != nil {
		t.Fatal(err)
	}
	current := g.CurrentSessionID()
	response := requestJSON(t, handler, "POST", "/api/infrareveal/simulation", "", "")
	if response.Code != 201 {
		t.Fatalf("start beside continuous demo: %s", response.Body.String())
	}
	if err := g.ensureDemoSession(); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() != current {
		t.Fatal("synthetic run replaced continuous demo")
	}
	if stop := requestJSON(t, handler, "DELETE", "/api/infrareveal/simulation", "", ""); stop.Code != 204 {
		t.Fatal(stop.Body.String())
	}
	if g.CurrentSessionID() != current {
		t.Fatal("cleanup replaced continuous demo")
	}
}
