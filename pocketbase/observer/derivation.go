package observer

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/debugtrace"
	"net/netip"
	"reflect"
	"time"
)

// deriveSession reads each input collection once inside one transaction. DNS
// candidates are indexed by client and answer; grouping consumes the installed
// conclusion, including stronger evidence that rejects a proposed downgrade.
func deriveSession(app core.App, scope ObservationScope, sessionID string, trace debugtrace.Sink) ([]DestinationObservation, error) {
	var destinations []DestinationObservation
	var events []debugtrace.Event
	err := app.RunInTransaction(func(tx core.App) error {
		rows := make(map[string][]*core.Record, 5)
		for _, name := range []string{"flows", "dns_queries", "flow_attributions", "activity_episodes", "flow_associations"} {
			var err error
			rows[name], err = tx.FindAllRecords(name, dbx.HashExp{"session": sessionID})
			if err != nil {
				return err
			}
		}
		attrs := indexRecords(rows["flow_attributions"], "flow")
		dns := map[string][]DNSObservation{}
		for _, record := range rows["dns_queries"] {
			observation := dnsObservationFromRecord(record)
			seen := map[string]bool{}
			for _, answer := range observation.Answers {
				if ip, err := netip.ParseAddr(answer); err == nil {
					key := observation.ClientIP + "|" + ip.Unmap().String()
					if !seen[key] {
						dns[key] = append(dns[key], observation)
						seen[key] = true
					}
				}
			}
		}
		flows := make([]AttributedFlowObservation, 0, len(rows["flows"]))
		for _, record := range rows["flows"] {
			flow := flowObservationFromRecord(record)
			installed := attrs[flow.ID]
			if scope.Includes(flow.Protocol, flow.ClientIP, flow.DestinationIP, flow.DestinationPort) {
				ip, _ := netip.ParseAddr(flow.DestinationIP)
				conclusion := AttributeFlow(flow, dns[flow.ClientIP+"|"+ip.Unmap().String()], dnsAttributionWindow)
				var changed bool
				var err error
				installed, changed, err = installAttribution(tx, flow, conclusion, installed)
				if err != nil {
					return err
				}
				if changed {
					events = append(events, debugtrace.Event{
						ID: traceEventID("flow-attribution", flow.ID, conclusion.ObservedAt), SessionID: flow.SessionID, TraceID: "flow:" + flow.ID,
						Kind: debugtrace.KindAttribution, Stage: debugtrace.StageAttribution, OccurredAtMs: conclusion.ObservedAt.UnixMilli(), ProcessedAtMs: traceProcessedNow(), Timing: debugtrace.TimingDerived,
						Summary: debugtrace.Summary{Protocol: flow.Protocol, ClientIP: flow.ClientIP, ClientPort: tracePort(flow.SourcePort), RemoteIP: flow.DestinationIP, RemotePort: tracePort(flow.DestinationPort), FlowKey: flow.FlowKey, Hostname: conclusion.CandidateHostname, Confidence: conclusion.Confidence},
					})
				}
			}
			observed := AttributedFlowObservation{Flow: flow}
			if installed != nil {
				observed.Hostname = installed.GetString("candidate_hostname")
				observed.Confidence = installed.GetString("confidence")
			}
			flows = append(flows, observed)
		}
		episodes, associations := InferActivityAssociations(flows)
		existingGroups := indexRecords(rows["activity_episodes"], "episode_key")
		ids, err := syncActivityEpisodes(tx, sessionID, episodes, existingGroups)
		if err != nil {
			return err
		}
		if err := syncFlowAssociations(tx, sessionID, associations, ids, indexRecords(rows["flow_associations"], "flow")); err != nil {
			return err
		}
		if err := removeStaleActivityEpisodes(tx, sessionID, episodes, existingGroups); err != nil {
			return err
		}
		destinations = uniqueDestinationObservations(rows["flows"], scope)
		return nil
	})
	if err == nil {
		for _, event := range events {
			trace.TryEmit(event)
		}
	}
	return destinations, err
}

func indexRecords(records []*core.Record, key string) map[string]*core.Record {
	result := make(map[string]*core.Record, len(records))
	for _, record := range records {
		result[record.GetString(key)] = record
	}
	return result
}

// Compare normalized schema values, including explanations and source times.
// An unchanged pass produces no save hooks or realtime updates.
func saveDerivedRecord(app core.App, record *core.Record) error {
	original := record.Original()
	if !record.IsNew() {
		changed := false
		for _, field := range record.Collection().Fields {
			name := field.GetName()
			if !reflect.DeepEqual(original.Get(name), record.Get(name)) {
				changed = true
				break
			}
		}
		if !changed {
			return nil
		}
	}
	return app.Save(record)
}

func installAttribution(app core.App, flow FlowObservation, conclusion AttributionConclusion, record *core.Record) (*core.Record, bool, error) {
	created := record == nil
	if created {
		collection, err := app.FindCollectionByNameOrId("flow_attributions")
		if err != nil {
			return nil, false, err
		}
		record = core.NewRecord(collection)
		record.Set("session", flow.SessionID)
		record.Set("flow", flow.ID)
	} else if !shouldReplaceAttribution(record.GetString("confidence"), record.GetString("candidate_hostname"), conclusion) {
		return record, false, nil
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
	if err := saveDerivedRecord(app, record); err != nil {
		return nil, false, err
	}
	return record, materialChange, nil
}

func syncActivityEpisodes(app core.App, sessionID string, episodes []ActivityEpisodeConclusion, existing map[string]*core.Record) (map[string]string, error) {
	ids := make(map[string]string, len(episodes))
	collection, err := app.FindCollectionByNameOrId("activity_episodes")
	if err != nil {
		return nil, err
	}
	for _, episode := range episodes {
		record := existing[episode.Key]
		if record == nil {
			record = core.NewRecord(collection)
		}
		record.Set("session", sessionID)
		record.Set("episode_key", episode.Key)
		record.Set("client_ip", episode.ClientIP)
		record.Set("site_key", episode.SiteKey)
		record.Set("label", episode.Label)
		record.Set("anchor_hostname", episode.AnchorHostname)
		record.Set("start", episode.Start.UTC().Format(time.RFC3339))
		record.Set("last_seen", episode.LastSeen.UTC().Format(time.RFC3339))
		record.Set("confidence", episode.Confidence)
		record.Set("explanation", episode.Explanation)
		if err := saveDerivedRecord(app, record); err != nil {
			return nil, err
		}
		ids[episode.Key] = record.Id
	}
	return ids, nil
}

func removeStaleActivityEpisodes(app core.App, sessionID string, episodes []ActivityEpisodeConclusion, existing map[string]*core.Record) error {
	desired := make(map[string]bool, len(episodes))
	for _, episode := range episodes {
		desired[episode.Key] = true
	}
	for _, record := range existing {
		if !desired[record.GetString("episode_key")] {
			if err := app.Delete(record); err != nil {
				return err
			}
		}
	}
	return nil
}

func syncFlowAssociations(app core.App, sessionID string, associations []FlowAssociationConclusion, episodeIDs map[string]string, existing map[string]*core.Record) error {
	desired := make(map[string]bool, len(associations))
	collection, err := app.FindCollectionByNameOrId("flow_associations")
	if err != nil {
		return err
	}
	for _, association := range associations {
		episodeID := episodeIDs[association.EpisodeKey]
		if episodeID == "" {
			continue
		}
		desired[association.FlowID] = true
		record := existing[association.FlowID]
		if record == nil {
			record = core.NewRecord(collection)
		}
		record.Set("session", sessionID)
		record.Set("flow", association.FlowID)
		record.Set("episode", episodeID)
		record.Set("parent_site_key", association.ParentSiteKey)
		record.Set("parent_label", association.ParentLabel)
		record.Set("relationship", association.Relationship)
		record.Set("confidence", association.Confidence)
		record.Set("score", association.Score)
		record.Set("explanation", association.Explanation)
		record.Set("observed_at", association.ObservedAt.UTC().Format(time.RFC3339))
		if err := saveDerivedRecord(app, record); err != nil {
			return err
		}
	}
	for _, record := range existing {
		if !desired[record.GetString("flow")] {
			if err := app.Delete(record); err != nil {
				return err
			}
		}
	}
	return nil
}
