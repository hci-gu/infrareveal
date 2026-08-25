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

func TestAttributeFlowUsesStartForLongLivedConnection(t *testing.T) {
	start := time.Date(2026, 8, 25, 8, 46, 0, 0, time.UTC)
	flow := FlowObservation{
		ClientIP: "10.0.0.96", DestinationIP: "92.122.72.194",
		DestinationPort: 443, Protocol: "tcp", Start: start, LastSeen: start.Add(20 * time.Minute),
	}
	dns := []DNSObservation{
		{ID: "original", ClientIP: "10.0.0.96", QueryName: "www.svt.se", Answers: []string{"92.122.72.194"}, Timestamp: start.Add(-3 * time.Second)},
		{ID: "later", ClientIP: "10.0.0.96", QueryName: "unrelated.example", Answers: []string{"92.122.72.194"}, Timestamp: start.Add(10 * time.Minute)},
	}

	conclusion := AttributeFlow(flow, dns, 5*time.Minute)
	if conclusion.CandidateHostname != "www.svt.se" {
		t.Fatalf("expected start-time attribution to remain www.svt.se, got %q", conclusion.CandidateHostname)
	}
}

func TestShouldReplaceAttributionOnlyUpgradesOrFillsEqualEvidence(t *testing.T) {
	mediumSVT := AttributionConclusion{Confidence: "medium", CandidateHostname: "www.svt.se"}
	mediumOther := AttributionConclusion{Confidence: "medium", CandidateHostname: "other.example"}
	low := AttributionConclusion{Confidence: "low"}

	if !shouldReplaceAttribution("low", "", mediumSVT) {
		t.Fatal("expected medium evidence to replace low evidence")
	}
	if shouldReplaceAttribution("medium", "www.svt.se", low) {
		t.Fatal("expected low evidence not to replace medium evidence")
	}
	if shouldReplaceAttribution("medium", "www.svt.se", mediumOther) {
		t.Fatal("expected an equal-confidence hostname not to replace the original hostname")
	}
}

func TestAttributeFlowPrefersOriginalCNAMEQueryWhenTimingTies(t *testing.T) {
	now := time.Date(2026, 8, 25, 8, 46, 0, 0, time.UTC)
	flow := FlowObservation{ClientIP: "10.0.0.96", DestinationIP: "92.122.72.194", Start: now}
	dns := []DNSObservation{
		{ID: "alias", ClientIP: "10.0.0.96", QueryName: "e6703.dscb.akamaiedge.net", Answers: []string{"92.122.72.194"}, Timestamp: now.Add(-3 * time.Second)},
		{ID: "original", ClientIP: "10.0.0.96", QueryName: "www.svt.se", Answers: []string{"92.122.72.194"}, Aliases: []string{"e6703.dscb.akamaiedge.net"}, Timestamp: now.Add(-3 * time.Second)},
	}

	conclusion := AttributeFlow(flow, dns, 5*time.Minute)
	if conclusion.CandidateHostname != "www.svt.se" {
		t.Fatalf("expected original CNAME query, got %q", conclusion.CandidateHostname)
	}
}
