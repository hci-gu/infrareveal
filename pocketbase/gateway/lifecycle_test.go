package gateway

import (
	"context"
	"github.com/pocketbase/pocketbase/core"
	"myapp/observer"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

func TestClearWaitsForObservationCommitAndSuppressesOldConntrack(t *testing.T) {
	app := ephemeralTestApp(t)
	g := testRuntime(t, app)
	g.Register()
	session := saveEphemeralFixture(t, app, "sessions", map[string]any{"active": true, "name": "clear race"})
	dir := t.TempDir()
	path := filepath.Join(dir, "conntrack")
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.50 dst=1.1.1.1 sport=53000 dport=443 packets=5 bytes=360 src=1.1.1.1 dst=10.0.0.50 sport=443 dport=53000 packets=7 bytes=600 [ASSURED] mark=0 zone=0 use=2\n"
	if err := os.WriteFile(path, []byte(line), 0600); err != nil {
		t.Fatal(err)
	}
	dnsPath := filepath.Join(dir, "dns.log")
	if err := os.WriteFile(dnsPath, nil, 0600); err != nil {
		t.Fatal(err)
	}
	config := g.config.Observation
	config.ConntrackPath = path
	config.DNSLogPath = dnsPath
	config.AccountingPath = ""
	config.SampleInterval = 20 * time.Millisecond
	config.Packet.Enabled = false
	g.observation = observer.New(app, nil, config, g.CurrentSessionID, nil, nil)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	app.OnRecordCreate("flows").BindFunc(func(e *core.RecordEvent) error { once.Do(func() { close(entered); <-release }); return e.Next() })
	g.observation.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("source did not reach flow persistence")
	}
	cleared := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := g.Clear(ctx)
		cleared <- err
	}()
	select {
	case err := <-cleared:
		t.Fatalf("clear acknowledged while old commit was blocked: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	close(release)
	if err := <-cleared; err != nil {
		t.Fatal(err)
	}
	time.Sleep(150 * time.Millisecond) // several source polls after restart
	for _, collection := range []string{"flows", "dns_queries", "flow_attributions", "activity_episodes", "flow_associations", "flow_activity_chunks"} {
		count, err := app.CountRecords(collection)
		if err != nil || count != 0 {
			t.Fatalf("pre-clear data returned in %s: %d %v", collection, count, err)
		}
	}
	if g.CurrentSessionID() != session.Id {
		t.Fatal("clear changed active session")
	}
	count, _ := app.CountRecords("sessions")
	if count != 1 {
		t.Fatal("clear removed session")
	}
}
