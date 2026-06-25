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
	DestinationPort int
	Protocol        string
	Start           time.Time
	LastSeen        time.Time
}

type DNSObservation struct {
	ID        string
	SessionID string
	ClientIP  string
	QueryName string
	Answers   []string
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

func StartFlowCorrelator(ctx context.Context, app *pocketbase.PocketBase, sessionID func() string) {
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
				if err := correlateSession(app, sessionID); err != nil {
					log.Printf("flow correlator error: %v", err)
				}
			}
		}
	}()
}

func correlateSession(app *pocketbase.PocketBase, sessionID string) error {
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
		conclusion := AttributeFlow(flow, dnsObservations, dnsAttributionWindow)
		if err := upsertAttribution(app, flow, conclusion); err != nil {
			return err
		}
	}

	return nil
}

func AttributeFlow(flow FlowObservation, dnsObservations []DNSObservation, window time.Duration) AttributionConclusion {
	best, ok := bestDNSMatch(flow, dnsObservations, window)
	observedAt := flow.LastSeen
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

	flowTime := flow.LastSeen
	if flowTime.IsZero() {
		flowTime = flow.Start
	}

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
		if !found || distance < bestDistance {
			best = dns
			bestDistance = distance
			found = true
		}
	}

	return best, found
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

func upsertAttribution(app *pocketbase.PocketBase, flow FlowObservation, conclusion AttributionConclusion) error {
	record, err := app.FindFirstRecordByFilter(
		"flow_attributions",
		"flow={:flow}",
		dbx.Params{"flow": flow.ID},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		collection, err := app.FindCollectionByNameOrId("flow_attributions")
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("session", flow.SessionID)
		record.Set("flow", flow.ID)
	}

	record.Set("candidate_hostname", conclusion.CandidateHostname)
	record.Set("source_signal", conclusion.SourceSignal)
	record.Set("confidence", conclusion.Confidence)
	record.Set("explanation", conclusion.Explanation)
	record.Set("dns_query", conclusion.DNSQueryID)
	record.Set("observed_at", conclusion.ObservedAt.UTC().Format(time.RFC3339))
	return app.Save(record)
}

func flowObservationFromRecord(record *core.Record) FlowObservation {
	return FlowObservation{
		ID:              record.Id,
		SessionID:       record.GetString("session"),
		ClientIP:        record.GetString("client_ip"),
		DestinationIP:   record.GetString("destination_ip"),
		DestinationPort: record.GetInt("destination_port"),
		Protocol:        strings.ToLower(record.GetString("protocol")),
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
