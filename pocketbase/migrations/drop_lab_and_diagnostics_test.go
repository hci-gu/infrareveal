package migrations_test

import (
	"strings"
	"testing"

	"github.com/pocketbase/pocketbase/core"
	"myapp/testsupport"
)

// An existing gateway database still carries the removed Proxy Lab and raw
// diagnostics schema; the migration must drop it without touching core data.
func TestDropLabAndDiagnosticsFromExistingDatabase(t *testing.T) {
	app := testsupport.App(t)
	for _, name := range []string{"gate_events", "flow_diagnostics", "dns_queries"} {
		c := core.NewBaseCollection(name)
		c.Fields.Add(&core.TextField{Name: "session"})
		if err := app.Save(c); err != nil {
			t.Fatal(err)
		}
	}
	sessions, _ := app.FindCollectionByNameOrId("sessions")
	sessions.Fields.Add(&core.JSONField{Name: "diagnostics", MaxSize: 1024}, &core.BoolField{Name: "gate_audit_complete"}, &core.NumberField{Name: "gate_audit_drops"})
	if err := app.Save(sessions); err != nil {
		t.Fatal(err)
	}
	runs, _ := app.FindCollectionByNameOrId("probe_runs")
	runs.Fields.Add(&core.JSONField{Name: "details", MaxSize: 16384})
	if err := app.Save(runs); err != nil {
		t.Fatal(err)
	}
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "kept", "gate_audit_complete": true})

	var up func(core.App) error
	for _, item := range core.AppMigrations.Items() {
		if strings.Contains(item.File, "drop_lab_and_diagnostics") {
			up = item.Up
		}
	}
	if up == nil {
		t.Fatal("migration not registered")
	}
	for range 2 { // idempotent against an already-clean schema
		if err := up(app); err != nil {
			t.Fatal(err)
		}
	}

	for _, name := range []string{"gate_events", "flow_diagnostics", "dns_queries"} {
		if _, err := app.FindCollectionByNameOrId(name); err == nil {
			t.Fatalf("%s survived", name)
		}
	}
	sessions, _ = app.FindCollectionByNameOrId("sessions")
	for _, field := range []string{"diagnostics", "gate_audit_complete", "gate_audit_drops"} {
		if sessions.Fields.GetByName(field) != nil {
			t.Fatalf("sessions.%s survived", field)
		}
	}
	runs, _ = app.FindCollectionByNameOrId("probe_runs")
	if runs.Fields.GetByName("details") != nil {
		t.Fatal("probe_runs.details survived")
	}
	if kept, err := app.FindRecordById("sessions", session.Id); err != nil || kept.GetString("name") != "kept" {
		t.Fatal("session data lost", err)
	}
}
