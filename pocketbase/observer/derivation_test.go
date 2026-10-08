package observer

import (
	"context"
	"database/sql"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/debugtrace"
	"strings"
	"testing"
	"time"
)

func TestDerivationSourceRecordsNoOpAndRejectedDowngrade(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	flow := createActivityTestFlow(t, app, session.Id, "derive-flow")
	now := time.Now().UTC().Truncate(time.Second)
	flow.Set("client_ip", "10.0.0.50")
	flow.Set("destination_ip", "1.1.1.1")
	flow.Set("destination_port", 443)
	flow.Set("protocol", "tcp")
	flow.Set("start", now)
	flow.Set("last_seen", now)
	if err := app.Save(flow); err != nil {
		t.Fatal(err)
	}
	collection, _ := app.FindCollectionByNameOrId("dns_queries")
	dns := core.NewRecord(collection)
	dns.Set("session", session.Id)
	dns.Set("client_ip", "10.0.0.50")
	dns.Set("query_name", "www.example.com")
	dns.Set("answers", []string{"1.1.1.1"})
	dns.Set("timestamp", now)
	if err := app.Save(dns); err != nil {
		t.Fatal(err)
	}
	scope := NewObservationScope("10.0.0.", "10.0.0.1")
	destinations, err := deriveSession(app, scope, session.Id, debugtrace.NopSink{})
	if err != nil {
		t.Fatal(err)
	}
	if len(destinations) != 1 || destinations[0].IP != "1.1.1.1" {
		t.Fatal(destinations)
	}
	attr, err := app.FindFirstRecordByFilter("flow_attributions", "flow={:f}", dbx.Params{"f": flow.Id})
	if err != nil {
		t.Fatal(err)
	}
	if attr.GetString("candidate_hostname") != "www.example.com" || attr.GetString("dns_query") != dns.Id {
		t.Fatal(attr)
	}
	group, err := app.FindFirstRecordByFilter("activity_episodes", "session={:s}", dbx.Params{"s": session.Id})
	if err != nil {
		t.Fatal(err)
	}
	groupID := group.Id
	saves := 0
	app.OnRecordUpdate("flow_attributions", "flow_associations", "activity_episodes").BindFunc(func(e *core.RecordEvent) error { saves++; return e.Next() })
	queries := map[string]int{}
	// All input reads in the transaction use the write DB's captured logger.
	db := app.NonconcurrentDB().(*dbx.DB)
	previous := db.QueryLogFunc
	db.QueryLogFunc = func(_ context.Context, _ time.Duration, query string, _ *sql.Rows, _ error) {
		for _, name := range []string{"flows", "dns_queries", "flow_attributions", "activity_episodes", "flow_associations"} {
			if strings.Contains(query, "FROM `"+name+"`") {
				queries[name]++
			}
		}
	}
	_, err = deriveSession(app, scope, session.Id, debugtrace.NopSink{})
	db.QueryLogFunc = previous
	if err != nil {
		t.Fatal(err)
	}
	if saves != 0 {
		t.Fatalf("unchanged derivation performed %d saves", saves)
	}
	for _, name := range []string{"flows", "dns_queries", "flow_attributions", "activity_episodes", "flow_associations"} {
		if queries[name] != 1 {
			t.Fatalf("expected one input query for %s: %#v", name, queries)
		}
	}
	t.Logf("unchanged pass: %d input queries, %d derived saves", 5, saves)
	attr.Set("candidate_hostname", "chat.discord.gg")
	attr.Set("confidence", "high")
	attr.Set("explanation", "installed stronger evidence")
	if err := app.Save(attr); err != nil {
		t.Fatal(err)
	}
	if _, err = deriveSession(app, scope, session.Id, debugtrace.NopSink{}); err != nil {
		t.Fatal(err)
	}
	group, err = app.FindFirstRecordByFilter("activity_episodes", "session={:s}", dbx.Params{"s": session.Id})
	if err != nil {
		t.Fatal(err)
	}
	if group.GetString("site_key") != "discord.com" || group.Id == groupID {
		t.Fatalf("group used rejected DNS conclusion: %s", group.GetString("site_key"))
	}
	attr, _ = app.FindRecordById("flow_attributions", attr.Id)
	if attr.GetString("explanation") != "installed stronger evidence" {
		t.Fatal("downgrade overwrote installed fields")
	}
}
