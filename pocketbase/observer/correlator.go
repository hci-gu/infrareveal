package observer

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

const dnsAttributionWindow = 5 * time.Minute

type FlowObservation struct {
	ID              string
	SessionID       string
	ClientIP        string
	DestinationIP   string
	SourcePort      int
	DestinationPort int
	Protocol        string
	FlowKey         string
	Start           time.Time
	LastSeen        time.Time
}

type DNSObservation struct {
	ID        string
	SessionID string
	ClientIP  string
	QueryName string
	Answers   []string
	Aliases   []string
	Timestamp time.Time
}

type AttributionConclusion struct {
	CandidateHostname string
	SourceSignal      string
	Confidence        string
	Explanation       string
	DNSQueryID        string
	ObservedAt        time.Time
}

func AttributeFlow(flow FlowObservation, dnsObservations []DNSObservation, window time.Duration) AttributionConclusion {
	best, ok := bestDNSMatch(flow, dnsObservations, window)
	observedAt := flowReferenceTime(flow)
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}

	if ok {
		delta := observedAt.Sub(best.Timestamp)
		if delta < 0 {
			delta = -delta
		}

		return AttributionConclusion{
			CandidateHostname: best.QueryName,
			SourceSignal:      "dns_answer",
			Confidence:        "medium",
			Explanation: fmt.Sprintf(
				"Client %s resolved %s to %s about %s before this flow was observed.",
				flow.ClientIP,
				best.QueryName,
				flow.DestinationIP,
				formatApproxDuration(delta),
			),
			DNSQueryID: best.ID,
			ObservedAt: observedAt,
		}
	}

	if hasReducedVisibilityPort(flow) {
		return AttributionConclusion{
			SourceSignal: "reduced_visibility",
			Confidence:   "hidden",
			Explanation: fmt.Sprintf(
				"No matching local DNS answer was observed for %s. This %s/%d flow uses a port commonly associated with encrypted or tunnelled traffic.",
				flow.DestinationIP,
				strings.ToUpper(flow.Protocol),
				flow.DestinationPort,
			),
			ObservedAt: observedAt,
		}
	}

	return AttributionConclusion{
		SourceSignal: "destination_ip",
		Confidence:   "low",
		Explanation: fmt.Sprintf(
			"Only destination IP %s was observed. No recent local DNS answer for this client matched the flow.",
			flow.DestinationIP,
		),
		ObservedAt: observedAt,
	}
}

func bestDNSMatch(flow FlowObservation, dnsObservations []DNSObservation, window time.Duration) (DNSObservation, bool) {
	var best DNSObservation
	var bestDistance time.Duration
	var found bool

	flowTime := flowReferenceTime(flow)

	for _, dns := range dnsObservations {
		if dns.ClientIP != flow.ClientIP {
			continue
		}
		if !answersContainIP(dns.Answers, flow.DestinationIP) {
			continue
		}

		distance := flowTime.Sub(dns.Timestamp)
		if distance < 0 {
			if -distance > 10*time.Second {
				continue
			}
			distance = -distance
		}
		if distance > window {
			continue
		}
		if !found || distance < bestDistance || (distance == bestDistance && len(dns.Aliases) > len(best.Aliases)) {
			best = dns
			bestDistance = distance
			found = true
		}
	}

	return best, found
}

func flowReferenceTime(flow FlowObservation) time.Time {
	if !flow.Start.IsZero() {
		return flow.Start
	}
	return flow.LastSeen
}

func answersContainIP(answers []string, destinationIP string) bool {
	parsedDestination := net.ParseIP(destinationIP)
	if parsedDestination == nil {
		return false
	}

	for _, answer := range answers {
		parsedAnswer := net.ParseIP(answer)
		if parsedAnswer == nil {
			continue
		}
		if parsedAnswer.Equal(parsedDestination) {
			return true
		}
	}
	return false
}

func hasReducedVisibilityPort(flow FlowObservation) bool {
	protocol := strings.ToLower(flow.Protocol)
	switch flow.DestinationPort {
	case 853, 51820:
		return true
	case 500, 4500:
		return protocol == "udp"
	case 443:
		return protocol == "udp"
	default:
		return false
	}
}

func shouldReplaceAttribution(existingConfidence, existingHostname string, next AttributionConclusion) bool {
	if confidenceRank(next.Confidence) > confidenceRank(existingConfidence) {
		return true
	}
	if confidenceRank(next.Confidence) < confidenceRank(existingConfidence) {
		return false
	}
	return existingHostname == "" || existingHostname == next.CandidateHostname
}

func confidenceRank(confidence string) int {
	switch confidence {
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "hidden":
		return 1
	default:
		return 0
	}
}

func flowObservationFromRecord(record *core.Record) FlowObservation {
	return FlowObservation{
		ID:              record.Id,
		SessionID:       record.GetString("session"),
		ClientIP:        record.GetString("client_ip"),
		DestinationIP:   record.GetString("destination_ip"),
		SourcePort:      record.GetInt("source_port"),
		DestinationPort: record.GetInt("destination_port"),
		Protocol:        strings.ToLower(record.GetString("protocol")),
		FlowKey:         record.GetString("flow_key"),
		Start:           record.GetDateTime("start").Time(),
		LastSeen:        record.GetDateTime("last_seen").Time(),
	}
}

func dnsObservationFromRecord(record *core.Record) DNSObservation {
	return DNSObservation{
		ID:        record.Id,
		SessionID: record.GetString("session"),
		ClientIP:  record.GetString("client_ip"),
		QueryName: record.GetString("query_name"),
		Answers:   record.GetStringSlice("answers"),
		Aliases:   record.GetStringSlice("aliases"),
		Timestamp: record.GetDateTime("timestamp").Time(),
	}
}

func formatApproxDuration(duration time.Duration) string {
	if duration < time.Second {
		return "less than a second"
	}
	if duration < time.Minute {
		return fmt.Sprintf("%d seconds", int(duration.Seconds()))
	}
	return fmt.Sprintf("%d minutes", int(duration.Minutes()))
}
