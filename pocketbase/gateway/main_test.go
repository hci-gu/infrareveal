package gateway

import (
	"context"
	"myapp/testsupport"
	"os"
	"path/filepath"
	"testing"
	"time"

	"myapp/observer"
)

func TestClearObservationsDeletesActivityBeforeFlows(t *testing.T) {
	app := testsupport.App(t)

	session := testsupport.Save(t, app, "sessions", map[string]any{
		"name": "Clear test",
	})
	flow := testsupport.Save(t, app, "flows", map[string]any{
		"session":          session.Id,
		"flow_key":         "tcp|10.0.0.50|53000|93.184.216.34|443",
		"client_ip":        "10.0.0.50",
		"destination_ip":   "93.184.216.34",
		"source_port":      53000,
		"destination_port": 443,
		"protocol":         "tcp",
		"start":            time.Now().UTC().Format(time.RFC3339Nano),
	})
	testsupport.Save(t, app, "flow_activity_chunks", map[string]any{
		"session":     session.Id,
		"flow":        flow.Id,
		"chunk_key":   "clear-test",
		"flow_key":    flow.GetString("flow_key"),
		"chunk_start": time.Now().UTC().Format(time.RFC3339Nano),
		"bucket_ms":   50,
		"chunk_ms":    5000,
		"samples":     map[string]any{"version": 1, "bucket_ms": 50, "chunk_ms": 5000, "samples": []any{}},
	})
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
