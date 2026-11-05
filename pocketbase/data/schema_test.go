package data_test

import (
	"testing"

	"myapp/data"
	"myapp/testsupport"
)

func TestFreshSchemaAndOptionalDiagnostics(t *testing.T) {
	app := testsupport.App(t)
	want := map[string]bool{"sessions": true, "traffic_chunks": true, "capture_intervals": true, "activity_blocks": true, "destinations": true, "route_evidence": true, "probe_runs": true}
	collections, err := app.FindAllCollections()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range collections {
		if c.System || c.Type == "auth" {
			continue
		}
		if !want[c.Name] {
			t.Fatalf("unexpected application collection %q", c.Name)
		}
		delete(want, c.Name)
		if c.ListRule != nil || c.CreateRule != nil {
			t.Fatalf("unbounded public access to %q", c.Name)
		}
	}
	if len(want) != 0 {
		t.Fatalf("missing collections: %v", want)
	}
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"flow_diagnostics", "dns_queries", "gate_events"} {
		if _, err := app.FindCollectionByNameOrId(name); err != nil {
			t.Fatal(err)
		}
	}
}

func TestTypedRoundTripRevisionAndActiveSessionConstraint(t *testing.T) {
	app := testsupport.App(t)
	s := data.Session{ID: data.NewID(), Name: "capture", Active: true, StartedMS: 1792050000000, Revision: 1, Policy: data.Policy{BucketMS: 50, Aliases: map[string]string{"svtplay.se": "svt.se"}}}
	r, err := data.Write(app, "sessions", s)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := data.Decode[data.Session](r)
	if err != nil || decoded.StartedMS != s.StartedMS || decoded.Policy.Aliases["svtplay.se"] != "svt.se" {
		t.Fatalf("round trip: %#v %v", decoded, err)
	}
	if err := data.BumpRevision(app, s.ID); err != nil {
		t.Fatal(err)
	}
	r, _ = app.FindRecordById("sessions", s.ID)
	if r.GetInt("revision") != 2 {
		t.Fatal("revision not incremented")
	}
	s.ID = data.NewID()
	if _, err := data.Write(app, "sessions", s); err == nil {
		t.Fatal("two active sessions allowed")
	}
}

func TestSimulationSchemaUpgradePreservesExistingRecording(t *testing.T) {
	app := testsupport.App(t)
	collection, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		t.Fatal(err)
	}
	collection.RemoveIndex("one_simulation")
	collection.RemoveIndex("one_active_session")
	collection.Fields.RemoveByName("simulation_expires_ms")
	collection.AddIndex("one_active_session", true, "active", "active = 1")
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	real := testsupport.Save(t, app, "sessions", map[string]any{"name": "recording", "active": true})
	data.SimulationFields(collection)
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	current, err := app.FindRecordById("sessions", real.Id)
	if err != nil || !current.GetBool("active") || current.GetInt64("simulation_expires_ms") != 0 {
		t.Fatalf("upgrade changed recording: %v", err)
	}
	simulation := data.Session{ID: data.NewID(), Active: true, SimulationExpiresMS: 1000}
	if _, err := data.Write(app, "sessions", simulation); err != nil {
		t.Fatal(err)
	}
	simulation.ID = data.NewID()
	if _, err := data.Write(app, "sessions", simulation); err == nil {
		t.Fatal("two simulations accepted")
	}
	if _, err := data.Write(app, "sessions", data.Session{ID: data.NewID(), Active: true}); err == nil {
		t.Fatal("upgrade removed real capture uniqueness")
	}
}
