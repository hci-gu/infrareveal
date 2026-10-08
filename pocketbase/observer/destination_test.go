package observer

import (
	"github.com/pocketbase/pocketbase/core"
	"testing"
	"time"
)

func TestProviderLabel(t *testing.T) {
	got := providerLabel("fra16s56-in-f14.1e100.net.")
	if got != "1e100.net" {
		t.Fatalf("expected 1e100.net, got %q", got)
	}
}

func TestKnownDestinationProviderRecognizesAppleNetwork(t *testing.T) {
	organization, provider := knownDestinationProvider(DestinationObservation{
		IP: "17.57.146.24", Protocol: "tcp", DestinationPort: 5223,
	})
	if organization != "Apple Inc." || provider != "Apple" {
		t.Fatalf("expected Apple provider labels, got %q / %q", organization, provider)
	}
}

func TestKnownDestinationProviderDoesNotGuessUnknownNetwork(t *testing.T) {
	organization, provider := knownDestinationProvider(DestinationObservation{IP: "92.122.72.194"})
	if organization != "" || provider != "" {
		t.Fatalf("expected no static provider guess, got %q / %q", organization, provider)
	}
}

func TestUniqueDestinationObservationsKeepsNewestPerIP(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	now := time.Now().UTC()
	first := createActivityTestFlow(t, app, session.Id, "first")
	second := createActivityTestFlow(t, app, session.Id, "second")
	for _, r := range []*core.Record{first, second} {
		r.Set("client_ip", "10.0.0.50")
		r.Set("destination_ip", "17.57.146.24")
		r.Set("protocol", "tcp")
		r.Set("destination_port", 443)
		r.Set("last_seen", now.Add(-time.Minute))
	}
	second.Set("last_seen", now)
	second.Set("destination_port", 5223)
	unique := uniqueDestinationObservations([]*core.Record{first, second}, NewObservationScope("10.0.0.", "10.0.0.1"))
	if len(unique) != 1 || unique[0].DestinationPort != 5223 {
		t.Fatalf("newest per IP: %#v", unique)
	}
}
