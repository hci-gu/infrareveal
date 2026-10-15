package gateway

import (
	"testing"

	"github.com/pocketbase/dbx"
	"myapp/testsupport"
)

func TestDemoStartupResumesOnlyActiveDedicatedSession(t *testing.T) {
	app := testsupport.App(t)
	t.Setenv("DEMO_MODE", "true")
	t.Setenv("DEMO_RETENTION_MINUTES", "30")
	g := testRuntime(t, app)
	old := testsupport.Save(t, app, "sessions", map[string]any{"name": "Recording", "active": true, "retention_minutes": 30, "started_ms": 1000})
	g.Register()
	if err := g.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	first := g.CurrentSessionID()
	if err := g.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() != first {
		t.Fatal("restart replaced active demo")
	}
	count, _ := app.CountRecords("sessions", dbx.HashExp{"demo": true})
	if count != 1 {
		t.Fatal(count)
	}
	rec, _ := app.FindRecordById("sessions", first)
	if !rec.GetBool("ephemeral") || rec.GetInt("retention_minutes") != 30 {
		t.Fatal("demo retention missing")
	}
	old, _ = app.FindRecordById("sessions", old.Id)
	if old.GetBool("active") || old.GetInt64("started_ms") != 1000 {
		t.Fatal("old recording lifecycle changed incorrectly")
	}
	rec.Set("active", false)
	if err := app.Save(rec); err != nil {
		t.Fatal(err)
	}
	if err := g.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() == first {
		t.Fatal("closed demo was reopened")
	}
	t.Setenv("DEMO_RETENTION_MINUTES", "invalid")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted invalid retention")
	}
}
