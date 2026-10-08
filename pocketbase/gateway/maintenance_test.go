package gateway

import (
	"errors"
	"github.com/pocketbase/pocketbase/core"
	"myapp/testsupport"
	"testing"
	"time"
)

func TestCatalogueFailureDoesNotDisableUnrelatedMaintenance(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.config.Demo = true
	g.config.DomainCatalogue = true
	now := time.Now().UTC()
	old := now.Add(-48 * time.Hour)
	demo := testsupport.Save(t, app, "sessions", map[string]any{"demo": true, "active": true, "ephemeral": true})
	dns := testsupport.Save(t, app, "dns_queries", map[string]any{"session": demo.Id, "query_name": "example.com", "timestamp": old})
	history := testsupport.Save(t, app, "sessions", map[string]any{"active": false})
	flow := testsupport.Save(t, app, "flows", map[string]any{"session": history.Id, "flow_key": "historical", "client_ip": "10.0.0.50", "destination_ip": "1.1.1.1", "protocol": "tcp", "start": old, "last_seen": old})
	testsupport.Save(t, app, "flow_activity_chunks", map[string]any{"session": history.Id, "flow": flow.Id, "chunk_key": "old", "flow_key": "historical", "samples": map[string]any{"version": 1, "bucket_ms": 50, "chunk_ms": 5000, "samples": []any{}}, "chunk_start": old, "chunk_ms": 5000, "bucket_ms": 50})
	testsupport.Save(t, app, "route_cache", map[string]any{"cache_key": "old-cache", "last_used_at": old})
	app.OnRecordCreate("domain_catalogue").BindFunc(func(e *core.RecordEvent) error { return errors.New("catalogue unavailable") })
	if err := g.sweep(now, true); err == nil {
		t.Fatal("maintenance hid catalogue failure")
	}
	if _, err := app.FindRecordById("dns_queries", dns.Id); err != nil {
		t.Fatal("failed aggregate transaction deleted source")
	}
	for _, name := range []string{"flow_activity_chunks", "route_cache"} {
		count, err := app.CountRecords(name)
		if err != nil || count != 0 {
			t.Fatalf("%s cleanup blocked: %d %v", name, count, err)
		}
	}
	if _, err := app.FindRecordById("flows", flow.Id); err != nil {
		t.Fatal("ordinary session history was deleted")
	}
}
