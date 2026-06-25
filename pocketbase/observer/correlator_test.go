package observer

import (
	"testing"
	"time"
)

func TestAttributeFlowReturnsMediumDNSMatch(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	flow := FlowObservation{
		ClientIP:        "10.0.0.50",
		DestinationIP:   "93.184.216.34",
		DestinationPort: 443,
		Protocol:        "tcp",
		LastSeen:        now,
	}
	dns := []DNSObservation{
		{
			ID:        "dns1",
			ClientIP:  "10.0.0.50",
			QueryName: "example.com",
			Answers:   []string{"93.184.216.34"},
			Timestamp: now.Add(-3 * time.Second),
		},
	}

	conclusion := AttributeFlow(flow, dns, 5*time.Minute)

	if conclusion.Confidence != "medium" {
		t.Fatalf("expected medium confidence, got %q", conclusion.Confidence)
	}
	if conclusion.CandidateHostname != "example.com" {
		t.Fatalf("expected example.com, got %q", conclusion.CandidateHostname)
	}
	if conclusion.DNSQueryID != "dns1" {
		t.Fatalf("expected dns query id dns1, got %q", conclusion.DNSQueryID)
	}
}

func TestAttributeFlowReturnsLowWithoutDNSMatch(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	flow := FlowObservation{
		ClientIP:        "10.0.0.50",
		DestinationIP:   "93.184.216.34",
		DestinationPort: 80,
		Protocol:        "tcp",
		LastSeen:        now,
	}

	conclusion := AttributeFlow(flow, nil, 5*time.Minute)

	if conclusion.Confidence != "low" {
		t.Fatalf("expected low confidence, got %q", conclusion.Confidence)
	}
	if conclusion.SourceSignal != "destination_ip" {
		t.Fatalf("expected destination_ip source, got %q", conclusion.SourceSignal)
	}
}

func TestAttributeFlowReturnsHiddenForReducedVisibilityPort(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	flow := FlowObservation{
		ClientIP:        "10.0.0.50",
		DestinationIP:   "1.1.1.1",
		DestinationPort: 853,
		Protocol:        "tcp",
		LastSeen:        now,
	}

	conclusion := AttributeFlow(flow, nil, 5*time.Minute)

	if conclusion.Confidence != "hidden" {
		t.Fatalf("expected hidden confidence, got %q", conclusion.Confidence)
	}
	if conclusion.SourceSignal != "reduced_visibility" {
		t.Fatalf("expected reduced_visibility source, got %q", conclusion.SourceSignal)
	}
}

func TestAttributeFlowIgnoresExpiredDNSMatch(t *testing.T) {
	now := time.Date(2026, 6, 25, 10, 0, 0, 0, time.UTC)
	flow := FlowObservation{
		ClientIP:        "10.0.0.50",
		DestinationIP:   "93.184.216.34",
		DestinationPort: 443,
		Protocol:        "tcp",
		LastSeen:        now,
	}
	dns := []DNSObservation{
		{
			ID:        "dns1",
			ClientIP:  "10.0.0.50",
			QueryName: "example.com",
			Answers:   []string{"93.184.216.34"},
			Timestamp: now.Add(-10 * time.Minute),
		},
	}

	conclusion := AttributeFlow(flow, dns, 5*time.Minute)

	if conclusion.Confidence != "low" {
		t.Fatalf("expected old DNS answer to be ignored, got %q", conclusion.Confidence)
	}
}
