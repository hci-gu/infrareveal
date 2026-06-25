package observer

import (
	"testing"
	"time"
)

func TestParseTracerouteOutput(t *testing.T) {
	output := []byte(`
traceroute to 93.184.216.34 (93.184.216.34), 20 hops max
 1  10.0.0.1  1.234 ms
 2  *
 3  93.184.216.34  12.345 ms
`)

	hops := ParseTracerouteOutput(output)

	if len(hops) != 3 {
		t.Fatalf("expected 3 hops, got %d", len(hops))
	}
	if hops[0].TTL != 1 || hops[0].Address != "10.0.0.1" || hops[0].Timings[0] != 1.234 {
		t.Fatalf("unexpected first hop: %#v", hops[0])
	}
	if !hops[1].Missing {
		t.Fatalf("expected second hop to be marked missing: %#v", hops[1])
	}
	if !routeComplete(hops, "93.184.216.34") {
		t.Fatal("expected route to be complete")
	}
}

func TestProviderLabel(t *testing.T) {
	got := providerLabel("fra16s56-in-f14.1e100.net.")
	if got != "1e100.net" {
		t.Fatalf("expected 1e100.net, got %q", got)
	}
}

func TestUniqueDestinationObservationsKeepsNewestPerRouteKey(t *testing.T) {
	now := time.Now().UTC()
	records := []*mockFlowRecord{
		{
			destinationIP:   "93.184.216.34",
			session:         "session1",
			destinationPort: 443,
			protocol:        "tcp",
			lastSeen:        now.Add(-time.Minute),
		},
		{
			destinationIP:   "93.184.216.34",
			session:         "session1",
			destinationPort: 443,
			protocol:        "tcp",
			lastSeen:        now,
		},
	}

	converted := make([]DestinationObservation, 0, len(records))
	for _, record := range records {
		converted = append(converted, DestinationObservation{
			IP:              record.destinationIP,
			SessionID:       record.session,
			DestinationPort: record.destinationPort,
			Protocol:        record.protocol,
			LastSeen:        record.lastSeen,
		})
	}

	seen := map[string]DestinationObservation{}
	for _, observation := range converted {
		key := routeKey(observation)
		existing, ok := seen[key]
		if !ok || observation.LastSeen.After(existing.LastSeen) {
			seen[key] = observation
		}
	}

	if len(seen) != 1 {
		t.Fatalf("expected one unique observation, got %d", len(seen))
	}
	for _, observation := range seen {
		if !observation.LastSeen.Equal(now) {
			t.Fatalf("expected newest observation, got %s", observation.LastSeen)
		}
	}
}

type mockFlowRecord struct {
	destinationIP   string
	session         string
	destinationPort int
	protocol        string
	lastSeen        time.Time
}
