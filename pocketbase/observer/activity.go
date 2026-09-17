package observer

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

type AttributedFlowObservation struct {
	Flow       FlowObservation
	Hostname   string
	Confidence string
}

type ActivityEpisodeConclusion struct {
	Key            string
	SessionID      string
	ClientIP       string
	SiteKey        string
	Label          string
	AnchorHostname string
	Start          time.Time
	LastSeen       time.Time
	Confidence     string
	Explanation    string
}

type FlowAssociationConclusion struct {
	FlowID        string
	EpisodeKey    string
	ParentSiteKey string
	ParentLabel   string
	Relationship  string
	Confidence    string
	Score         int
	Explanation   string
	ObservedAt    time.Time
}

func correlateActivitySession(app *pocketbase.PocketBase, sessionID string) error {
	flowRecords, err := app.FindAllRecords("flows", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
	}
	attributionRecords, err := app.FindAllRecords("flow_attributions", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
	}
	attributions := make(map[string]*core.Record, len(attributionRecords))
	for _, record := range attributionRecords {
		attributions[record.GetString("flow")] = record
	}
	flows := make([]AttributedFlowObservation, 0, len(flowRecords))
	for _, record := range flowRecords {
		flow := flowObservationFromRecord(record)
		attribution := attributions[flow.ID]
		if attribution == nil {
			flows = append(flows, AttributedFlowObservation{Flow: flow})
			continue
		}
		flows = append(flows, AttributedFlowObservation{
			Flow: flow, Hostname: attribution.GetString("candidate_hostname"),
			Confidence: attribution.GetString("confidence"),
		})
	}
	episodes, associations := InferActivityAssociations(flows)
	episodeIDs, err := syncActivityEpisodes(app, sessionID, episodes)
	if err != nil {
		return err
	}
	if err := syncFlowAssociations(app, sessionID, associations, episodeIDs); err != nil {
		return err
	}
	return removeStaleActivityEpisodes(app, sessionID, episodes)
}

// InferActivityAssociations groups attributed hostnames by registered domain and
// explicit aliases. DNS timing and connection gaps never establish membership.
func InferActivityAssociations(flows []AttributedFlowObservation) ([]ActivityEpisodeConclusion, []FlowAssociationConclusion) {
	sortedFlows := append([]AttributedFlowObservation(nil), flows...)
	sort.Slice(sortedFlows, func(i, j int) bool {
		if sortedFlows[i].Flow.Start.Equal(sortedFlows[j].Flow.Start) {
			return sortedFlows[i].Flow.ID < sortedFlows[j].Flow.ID
		}
		return sortedFlows[i].Flow.Start.Before(sortedFlows[j].Flow.Start)
	})
	episodes := []ActivityEpisodeConclusion{}
	associations := []FlowAssociationConclusion{}
	byKey := make(map[string]int)
	for _, observed := range sortedFlows {
		if !usableHostnameEvidence(observed) {
			continue
		}
		domain := registeredActivityDomain(observed.Hostname)
		if domain == "" {
			continue
		}
		site := domain
		relationship := "first_party"
		explanation := fmt.Sprintf("%s groups under its registered domain %s.", normalizeActivityHostname(observed.Hostname), domain)
		if canonical, matched, ok := activityGroupAlias(observed.Hostname, domain); ok {
			site = canonical
			relationship = "domain_alias"
			explanation = fmt.Sprintf("%s groups under %s through the explicit domain mapping %s → %s.", normalizeActivityHostname(observed.Hostname), site, matched, site)
		}
		flow := observed.Flow
		key := fmt.Sprintf("%s|%s|domain:%s", flow.SessionID, flow.ClientIP, site)
		index, exists := byKey[key]
		if !exists {
			index = len(episodes)
			byKey[key] = index
			episodes = append(episodes, ActivityEpisodeConclusion{
				Key: key, SessionID: flow.SessionID, ClientIP: flow.ClientIP,
				SiteKey: site, Label: site, AnchorHostname: normalizeActivityHostname(observed.Hostname),
				Start: flow.Start, LastSeen: flowEnd(flow), Confidence: observed.Confidence,
				Explanation: fmt.Sprintf("Connections grouped by registered domain %s and explicit domain aliases for this client and session.", site),
			})
		} else {
			if end := flowEnd(flow); end.After(episodes[index].LastSeen) {
				episodes[index].LastSeen = end
			}
			if confidenceRank(observed.Confidence) > confidenceRank(episodes[index].Confidence) {
				episodes[index].Confidence = observed.Confidence
			}
		}
		score := 80
		if observed.Confidence == "high" {
			score = 100
		}
		associations = append(associations, FlowAssociationConclusion{
			FlowID: flow.ID, EpisodeKey: key, ParentSiteKey: site, ParentLabel: site,
			Relationship: relationship, Confidence: observed.Confidence, Score: score,
			Explanation: explanation, ObservedAt: flow.Start,
		})
	}
	return episodes, associations
}

func usableHostnameEvidence(flow AttributedFlowObservation) bool {
	return flow.Hostname != "" && (flow.Confidence == "medium" || flow.Confidence == "high") && !flow.Flow.Start.IsZero()
}

func flowEnd(flow FlowObservation) time.Time {
	if flow.LastSeen.After(flow.Start) {
		return flow.LastSeen
	}
	return flow.Start
}

func syncActivityEpisodes(app *pocketbase.PocketBase, sessionID string, episodes []ActivityEpisodeConclusion) (map[string]string, error) {
	ids := make(map[string]string, len(episodes))
	collection, err := app.FindCollectionByNameOrId("activity_episodes")
	if err != nil {
		return nil, err
	}
	for _, episode := range episodes {
		record, err := app.FindFirstRecordByFilter("activity_episodes", "episode_key={:key}", dbx.Params{"key": episode.Key})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return nil, err
			}
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
		if err := app.Save(record); err != nil {
			return nil, err
		}
		ids[episode.Key] = record.Id
	}
	return ids, nil
}

func removeStaleActivityEpisodes(app *pocketbase.PocketBase, sessionID string, episodes []ActivityEpisodeConclusion) error {
	desired := make(map[string]bool, len(episodes))
	for _, episode := range episodes {
		desired[episode.Key] = true
	}
	existing, err := app.FindAllRecords("activity_episodes", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
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

func syncFlowAssociations(app *pocketbase.PocketBase, sessionID string, associations []FlowAssociationConclusion, episodeIDs map[string]string) error {
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
		record, err := app.FindFirstRecordByFilter("flow_associations", "flow={:flow}", dbx.Params{"flow": association.FlowID})
		if err != nil {
			if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
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
		if err := app.Save(record); err != nil {
			return err
		}
	}
	existing, err := app.FindAllRecords("flow_associations", dbx.HashExp{"session": sessionID})
	if err != nil {
		return err
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
