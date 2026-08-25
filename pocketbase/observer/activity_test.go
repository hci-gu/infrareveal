package observer

import (
	"testing"
	"time"
)

func TestInferActivityAssociationsGroupsFirstPartyAndFreshThirdParty(t *testing.T) {
	start := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	flows := []AttributedFlowObservation{
		activityFlow("svt", "www.svt.se", "dns-svt", start),
		activityFlow("cdn", "wm0.cdn.svt.se", "dns-cdn", start.Add(time.Second)),
		activityFlow("tracker", "tracker.example", "dns-tracker", start.Add(2*time.Second)),
		activityFlow("tracker-2", "tracker.example", "dns-tracker-2", start.Add(4*time.Second)),
	}
	dns := []DNSObservation{
		{ID: "dns-svt", ClientIP: "10.0.0.50", QueryName: "www.svt.se", Timestamp: start.Add(-time.Second)},
		{ID: "dns-cdn", ClientIP: "10.0.0.50", QueryName: "wm0.cdn.svt.se", Timestamp: start, Aliases: []string{"svt.akamaized.net"}},
		{ID: "dns-tracker", ClientIP: "10.0.0.50", QueryName: "tracker.example", Timestamp: start.Add(time.Second)},
		{ID: "dns-tracker-2", ClientIP: "10.0.0.50", QueryName: "tracker.example", Timestamp: start.Add(3 * time.Second)},
	}

	episodes, associations := InferActivityAssociations(flows, dns)
	if len(episodes) != 1 || episodes[0].SiteKey != "svt.se" {
		t.Fatalf("expected one SVT episode, got %#v", episodes)
	}
	byFlow := associationsByFlow(associations)
	if byFlow["svt"].Relationship != "first_party" || byFlow["svt"].Confidence != "high" {
		t.Fatalf("expected direct SVT traffic to be high-confidence first party, got %#v", byFlow["svt"])
	}
	if byFlow["cdn"].Relationship != "cname_related" || byFlow["cdn"].Confidence != "high" {
		t.Fatalf("expected CDN traffic to use CNAME evidence, got %#v", byFlow["cdn"])
	}
	if byFlow["tracker"].Relationship != "temporally_associated" || byFlow["tracker"].Confidence != "medium" {
		t.Fatalf("expected fresh tracker traffic to be medium-confidence associated, got %#v", byFlow["tracker"])
	}
	if byFlow["tracker-2"].Relationship != "temporally_associated" {
		t.Fatalf("expected subsequent fresh tracker requests in the episode to remain associated, got %#v", byFlow["tracker-2"])
	}
}

func TestInferActivityAssociationsLeavesPreexistingHostnameIndependent(t *testing.T) {
	start := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	flows := []AttributedFlowObservation{
		activityFlow("background", "tracker.example", "dns-old", start.Add(-20*time.Second)),
		activityFlow("svt", "www.svt.se", "dns-svt", start),
		activityFlow("tracker", "tracker.example", "dns-new", start.Add(2*time.Second)),
	}
	dns := []DNSObservation{
		{ID: "dns-old", ClientIP: "10.0.0.50", QueryName: "tracker.example", Timestamp: start.Add(-21 * time.Second)},
		{ID: "dns-svt", ClientIP: "10.0.0.50", QueryName: "www.svt.se", Timestamp: start.Add(-time.Second)},
		{ID: "dns-new", ClientIP: "10.0.0.50", QueryName: "tracker.example", Timestamp: start.Add(time.Second)},
	}

	_, associations := InferActivityAssociations(flows, dns)
	if _, exists := associationsByFlow(associations)["tracker"]; exists {
		t.Fatal("expected a hostname already active before the visit to remain independent")
	}
}

func TestInferActivityAssociationsRejectsAmbiguousParent(t *testing.T) {
	start := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	flows := []AttributedFlowObservation{
		activityFlow("svt", "www.svt.se", "dns-svt", start),
		activityFlow("youtube", "www.youtube.com", "dns-youtube", start),
		activityFlow("tracker", "tracker.example", "dns-tracker", start.Add(2*time.Second)),
	}
	dns := []DNSObservation{
		{ID: "dns-svt", ClientIP: "10.0.0.50", QueryName: "www.svt.se", Timestamp: start.Add(-time.Second)},
		{ID: "dns-youtube", ClientIP: "10.0.0.50", QueryName: "www.youtube.com", Timestamp: start.Add(-time.Second)},
		{ID: "dns-tracker", ClientIP: "10.0.0.50", QueryName: "tracker.example", Timestamp: start.Add(time.Second)},
	}

	_, associations := InferActivityAssociations(flows, dns)
	if _, exists := associationsByFlow(associations)["tracker"]; exists {
		t.Fatal("expected equally close competing website anchors to leave the request independent")
	}
}

func TestInferActivityAssociationsRequiresHostnameAndDNSForThirdParty(t *testing.T) {
	start := time.Date(2026, 8, 25, 10, 0, 0, 0, time.UTC)
	flows := []AttributedFlowObservation{
		activityFlow("svt", "www.svt.se", "dns-svt", start),
		{Flow: FlowObservation{ID: "unresolved", SessionID: "session", ClientIP: "10.0.0.50", DestinationIP: "1.1.1.1", DestinationPort: 443, Protocol: "udp", Start: start.Add(time.Second)}},
		activityFlow("missing-dns", "tracker.example", "", start.Add(2*time.Second)),
	}

	_, associations := InferActivityAssociations(flows, []DNSObservation{
		{ID: "dns-svt", ClientIP: "10.0.0.50", QueryName: "www.svt.se", Timestamp: start.Add(-time.Second)},
	})
	byFlow := associationsByFlow(associations)
	if _, exists := byFlow["unresolved"]; exists {
		t.Fatal("expected unresolved traffic to remain independent")
	}
	if _, exists := byFlow["missing-dns"]; exists {
		t.Fatal("expected third-party traffic without transaction-linked DNS to remain independent")
	}
}

func activityFlow(id, hostname, dnsID string, start time.Time) AttributedFlowObservation {
	return AttributedFlowObservation{
		Flow: FlowObservation{
			ID: id, SessionID: "session", ClientIP: "10.0.0.50", DestinationIP: "93.184.216.34",
			DestinationPort: 443, Protocol: "tcp", Start: start, LastSeen: start.Add(3 * time.Second),
		},
		Hostname: hostname, Confidence: "medium", DNSQueryID: dnsID,
	}
}

func associationsByFlow(associations []FlowAssociationConclusion) map[string]FlowAssociationConclusion {
	result := make(map[string]FlowAssociationConclusion, len(associations))
	for _, association := range associations {
		result[association.FlowID] = association
	}
	return result
}
