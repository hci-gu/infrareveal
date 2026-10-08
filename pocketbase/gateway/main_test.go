package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"

	"myapp/observer"
)

func TestClearObservationsDeletesActivityBeforeFlows(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })

	sessionCollection, _ := app.FindCollectionByNameOrId("sessions")
	session := core.NewRecord(sessionCollection)
	session.Set("name", "Clear test")
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	flowCollection, _ := app.FindCollectionByNameOrId("flows")
	flow := core.NewRecord(flowCollection)
	flow.Set("session", session.Id)
	flow.Set("flow_key", "tcp|10.0.0.50|53000|93.184.216.34|443")
	flow.Set("client_ip", "10.0.0.50")
	flow.Set("destination_ip", "93.184.216.34")
	flow.Set("source_port", 53000)
	flow.Set("destination_port", 443)
	flow.Set("protocol", "tcp")
	flow.Set("start", time.Now().UTC().Format(time.RFC3339Nano))
	if err := app.Save(flow); err != nil {
		t.Fatal(err)
	}
	chunkCollection, _ := app.FindCollectionByNameOrId("flow_activity_chunks")
	chunk := core.NewRecord(chunkCollection)
	chunk.Set("session", session.Id)
	chunk.Set("flow", flow.Id)
	chunk.Set("chunk_key", "clear-test")
	chunk.Set("flow_key", flow.GetString("flow_key"))
	chunk.Set("chunk_start", time.Now().UTC().Format(time.RFC3339Nano))
	chunk.Set("bucket_ms", 50)
	chunk.Set("chunk_ms", 5000)
	chunk.Set("samples", map[string]any{"version": 1, "bucket_ms": 50, "chunk_ms": 5000, "samples": []any{}})
	if err := app.Save(chunk); err != nil {
		t.Fatal(err)
	}
	conntrackPath := filepath.Join(t.TempDir(), "nf_conntrack")
	conntrackLine := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.50 dst=93.184.216.34 sport=53000 dport=443 packets=5 bytes=360 src=93.184.216.34 dst=10.0.0.50 sport=443 dport=53000 packets=7 bytes=600 [ASSURED] mark=0 zone=0 use=2\n"
	if err := os.WriteFile(conntrackPath, []byte(conntrackLine), 0o644); err != nil {
		t.Fatal(err)
	}
	g := testRuntime(t, app)
	config := g.config.Observation
	config.ConntrackPath = conntrackPath
	g.observation = observer.New(app, nil, config, g.CurrentSessionID, nil, nil)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})

	result, err := g.Clear(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if result.Deleted["flow_activity_chunks"] != 1 || result.Deleted["flows"] != 1 {
		t.Fatalf("expected activity and flow records deleted, got %#v", result.Deleted)
	}
	samples, err := observer.ReadConntrackSamples(conntrackPath, config.Scope)
	if err != nil {
		t.Fatal(err)
	}
	if len(samples) != 1 {
		t.Fatalf("fixture conntrack input changed, got %#v", samples)
	}
}
