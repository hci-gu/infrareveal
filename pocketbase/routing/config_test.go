package routing

import (
	"path/filepath"
	"testing"
	"time"
)

func TestCapturedConfigSurvivesEnvironmentChanges(t *testing.T) {
	t.Setenv("ROUTE_MAX_TARGETS", "1")
	t.Setenv("ROUTE_ASN_DB", filepath.Join(t.TempDir(), "captured.mmdb"))
	config := ConfigFromEnv()
	t.Setenv("ROUTE_MAX_TARGETS", "100")
	t.Setenv("ROUTE_ASN_DB", filepath.Join(t.TempDir(), "changed.mmdb"))

	app := testApp(t)
	session := testSession(t, app)
	store := newEvidenceStore(app, nil, config)
	if store.limits().ASNDBPath != config.ASNDBPath {
		t.Fatal("ASN database path changed after configuration was captured")
	}
	now := time.Now()
	binding := routeBinding{Session: session, Network: "network", Target: target{"9.9.9.9", "tcp", 443}}
	first, err := store.reserve(binding, false, now)
	if err != nil || first.Reason != "" {
		t.Fatalf("first admission: %+v %v", first, err)
	}
	binding.Target.IP = "8.8.8.8"
	second, err := store.reserve(binding, false, now.Add(time.Second))
	if err != nil || second.Reason != "target_budget" {
		t.Fatalf("environment changed captured target allowance: %+v %v", second, err)
	}
	if got := (evidenceStore{app: app}).limits(); got != defaultConfig() {
		t.Fatalf("unconfigured fixture store read environment: %+v", got)
	}
}
