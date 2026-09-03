package observer

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net"
	"strings"
	"time"

	"myapp/debugtrace"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
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

func StartFlowCorrelator(ctx context.Context, app *pocketbase.PocketBase, scope ObservationScope, sessionID func() string, trace debugtrace.Sink) {
	trace = usableTraceSink(trace)
	go func() {
		ticker := time.NewTicker(3 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				sessionID := sessionID()
				if sessionID == "" {
					continue
				}
				if err := correlateSession(app, scope, sessionID, trace); err != nil {
					log.Printf("flow correlator error: %v", err)
					continue
				}
				if err := correlateActivitySession(app, sessionID); err != nil {
					log.Printf("activity correlator error: %v", err)
				}
			}
		}
	}()
}

func correlateSession(app *pocketbase.PocketBase, scope ObservationScope, sessionID string, trace debugtrace.Sink) error {
	flowRecords, err := app.FindAllRecords("flows", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
	}

	dnsRecords, err := app.FindAllRecords("dns_queries", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
	}

	dnsObservations := make([]DNSObservation, 0, len(dnsRecords))
	for _, record := range dnsRecords {
		dnsObservations = append(dnsObservations, dnsObservationFromRecord(record))
	}

	for _, record := range flowRecords {
		flow := flowObservationFromRecord(record)
		if !scope.Includes(flow.Protocol, flow.ClientIP, flow.DestinationIP, flow.DestinationPort) {
			continue
		}
		conclusion := AttributeFlow(flow, dnsObservations, dnsAttributionWindow)
		changed, err := upsertAttribution(app, flow, conclusion)
		if err != nil {
			return err
		}
		if changed {
			trace.TryEmit(debugtrace.Event{
				ID:        traceEventID("flow-attribution", flow.ID, conclusion.ObservedAt),
				SessionID: flow.SessionID, TraceID: "flow:" + flow.ID,
				Kind: debugtrace.KindAttribution, Stage: debugtrace.StageAttribution,
				OccurredAtMs: conclusion.ObservedAt.UnixMilli(), ProcessedAtMs: traceProcessedNow(), Timing: debugtrace.TimingDerived,
				Summary: debugtrace.Summary{
					Protocol: flow.Protocol, ClientIP: flow.ClientIP, ClientPort: tracePort(flow.SourcePort),
					RemoteIP: flow.DestinationIP, RemotePort: tracePort(flow.DestinationPort), FlowKey: flow.FlowKey,
					Hostname: conclusion.CandidateHostname, Confidence: conclusion.Confidence,
				},
			})
		}
	}

	return nil
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

func upsertAttribution(app *pocketbase.PocketBase, flow FlowObservation, conclusion AttributionConclusion) (bool, error) {
	created := false
	record, err := app.FindFirstRecordByFilter(
		"flow_attributions",
		"flow={:flow}",
		dbx.Params{"flow": flow.ID},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return false, err
		}
		collection, err := app.FindCollectionByNameOrId("flow_attributions")
		if err != nil {
			return false, err
		}
		record = core.NewRecord(collection)
		created = true
		record.Set("session", flow.SessionID)
		record.Set("flow", flow.ID)
	} else if !shouldReplaceAttribution(record.GetString("confidence"), record.GetString("candidate_hostname"), conclusion) {
		return false, nil
	}
	materialChange := created ||
		record.GetString("candidate_hostname") != conclusion.CandidateHostname ||
		record.GetString("source_signal") != conclusion.SourceSignal ||
		record.GetString("confidence") != conclusion.Confidence ||
		record.GetString("dns_query") != conclusion.DNSQueryID

	record.Set("candidate_hostname", conclusion.CandidateHostname)
	record.Set("source_signal", conclusion.SourceSignal)
	record.Set("confidence", conclusion.Confidence)
	record.Set("explanation", conclusion.Explanation)
	record.Set("dns_query", conclusion.DNSQueryID)
	record.Set("observed_at", conclusion.ObservedAt.UTC().Format(time.RFC3339))
	if err := app.Save(record); err != nil {
		return false, err
	}
	return materialChange, nil
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
