package gateway

import (
	"fmt"
	"myapp/testsupport"
	"myapp/timeline"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/observer"
)

func TestDemoStartupResumesDedicatedSession(t *testing.T) {
	app := testsupport.App(t)
	t.Setenv("DEMO_MODE", "true")
	t.Setenv("DEMO_RETENTION_MINUTES", "30")
	g := testRuntime(t, app)
	old := testsupport.Save(t, app, "sessions", map[string]any{"name": "Recording", "active": true})
	g.Register()
	if err := g.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	first := g.CurrentSessionID()
	if err := g.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() != first {
		t.Fatal("restart created another session")
	}
	count, _ := app.CountRecords("sessions", dbx.HashExp{"demo": true})
	if count != 1 {
		t.Fatal(count)
	}
	rec, _ := app.FindRecordById("sessions", first)
	if !rec.GetBool("ephemeral") || rec.GetInt("retention_minutes") != 30 {
		t.Fatal(rec)
	}
	old, _ = app.FindRecordById("sessions", old.Id)
	if old.GetBool("active") {
		t.Fatal("old recording still active")
	}
	t.Setenv("DEMO_RETENTION_MINUTES", "invalid")
	if _, err := ConfigFromEnv(); err == nil {
		t.Fatal("accepted invalid retention")
	}
}

func TestThirtyMinuteRetentionAndCatalogueSurviveCleanup(t *testing.T) {
	app := testsupport.App(t)
	t.Setenv("DEMO_MODE", "true")
	now := time.Now().UTC()
	start := now.Add(-time.Hour)
	session := testsupport.Save(t, app, "sessions", map[string]any{"demo": true, "ephemeral": true, "active": true, "retention_minutes": 30, "started_at": start})
	for i, age := range []time.Duration{31 * time.Minute, 20 * time.Minute} {
		testsupport.Save(t, app, "dns_queries", map[string]any{"session": session.Id, "query_name": fmt.Sprintf("www%d.example.com", i), "timestamp": now.Add(-age), "aliases": []string{"edge.cdn.net"}})
		testsupport.Save(t, app, "flows", map[string]any{"session": session.Id, "flow_key": fmt.Sprint(i), "protocol": "tcp", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "start": now.Add(-age), "last_seen": now.Add(-age)})
	}
	if err := testRuntime(t, app).pruneEphemeralSessions(now); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"flows", "dns_queries"} {
		n, _ := app.CountRecords(name)
		if n != 1 {
			t.Fatalf("%s=%d", name, n)
		}
	}
	cat, err := app.FindFirstRecordByFilter("domain_catalogue", "domain='example.com'")
	if err != nil {
		t.Fatal(err)
	}
	if cat.GetInt("dns_count") != 2 {
		t.Fatal("cleanup lost aggregate", cat.GetInt("dns_count"))
	}
	if err := testRuntime(t, app).pruneEphemeralSessions(now.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	cat, _ = app.FindRecordById("domain_catalogue", cat.Id)
	if cat.GetInt("dns_count") != 2 {
		t.Fatal("aggregate counted twice")
	}
	manifest, err := timeline.New(app).Manifest(session.Id, now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if manifest.RetentionMinutes != 30 || manifest.StartedAt != now.Add(30*time.Minute).Format(time.RFC3339Nano) {
		t.Fatal(manifest)
	}
}

func TestCatalogueRevisionIdempotenceAndBoundedExamples(t *testing.T) {
	app := testsupport.App(t)
	now := time.Now().UTC()
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true})
	dns := testsupport.Save(t, app, "dns_queries", map[string]any{"session": session.Id, "query_name": "www.example.com", "timestamp": now})
	flow := testsupport.Save(t, app, "flows", map[string]any{"session": session.Id, "flow_key": "one", "protocol": "tcp", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "start": now, "last_seen": now})
	attr := testsupport.Save(t, app, "flow_attributions", map[string]any{"session": session.Id, "flow": flow.Id, "candidate_hostname": "www.example.com", "confidence": "medium", "source_signal": "dns_answer", "observed_at": now})
	collect := func() {
		t.Helper()
		if err := observer.CollectDomainCatalogue(app, session.Id); err != nil {
			t.Fatal(err)
		}
	}
	collect()
	collect()
	// Simulate a later DNS answer and confidence correction, without sleeping.
	aliases := []string{}
	for i := 0; i < 40; i++ {
		aliases = append(aliases, fmt.Sprintf("cdn%d.other.net", i))
	}
	dns.Set("aliases", aliases)
	if err := app.Save(dns); err != nil {
		t.Fatal(err)
	}
	attr, _ = app.FindRecordById("flow_attributions", attr.Id)
	attr.Set("confidence", "high")
	attr.Set("candidate_hostname", "api.other.net")
	if err := app.Save(attr); err != nil {
		t.Fatal(err)
	}
	collect()
	collect()
	first, _ := app.FindFirstRecordByFilter("domain_catalogue", "domain='example.com'")
	second, _ := app.FindFirstRecordByFilter("domain_catalogue", "domain='other.net'")
	if first.GetInt("dns_count") != 1 || first.GetInt("medium_flow_count") != 0 || second.GetInt("high_flow_count") != 1 {
		t.Fatal("revisions double-counted")
	}
	var examples []any
	if err := first.UnmarshalJSONField("cname_examples", &examples); err != nil {
		t.Fatal(err)
	}
	if len(examples) != 16 {
		t.Fatal(len(examples))
	}
	// An aborted aggregate transaction must also roll back source checkpoints.
	extra := testsupport.Save(t, app, "dns_queries", map[string]any{"session": session.Id, "query_name": "test.example.com", "timestamp": now})
	_ = app.RunInTransaction(func(tx core.App) error {
		if err := observer.CollectDomainCatalogue(tx, session.Id); err != nil {
			return err
		}
		return fmt.Errorf("simulated crash")
	})
	var checkpointCount struct {
		N int `db:"n"`
	}
	if err := app.DB().NewQuery("SELECT count(*) n FROM _domain_catalogue_checkpoints WHERE source_id={:id}").Bind(dbx.Params{"id": extra.Id}).One(&checkpointCount); err != nil {
		t.Fatal(err)
	}
	if checkpointCount.N != 0 {
		t.Fatal("checkpoint escaped rollback")
	}
	collect()
	first, _ = app.FindRecordById("domain_catalogue", first.Id)
	if first.GetInt("dns_count") != 2 {
		t.Fatal("rollback lost count")
	}
}
