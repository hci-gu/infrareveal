package observer

import (
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

const (
	activityEpisodeGap        = 30 * time.Second
	temporalAssociationWindow = 8 * time.Second
	dnsAssociationTolerance   = 2 * time.Second
)

type AttributedFlowObservation struct {
	Flow       FlowObservation
	Hostname   string
	Confidence string
	DNSQueryID string
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
	AnchorTimes    []time.Time
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

type siteFamily struct {
	Key     string
	Label   string
	Domains []string
}

var anchorSiteFamilies = []siteFamily{
	{Key: "svt.se", Label: "svt.se", Domains: []string{"svt.se", "svtstatic.se", "svtplay.se"}},
	{Key: "spotify", Label: "Spotify", Domains: []string{"spotify.com", "spotifycdn.com", "spotifycdn.net", "scdn.co", "pscdn.co"}},
	{Key: "youtube", Label: "YouTube", Domains: []string{"youtube.com", "youtu.be", "ytimg.com", "googlevideo.com"}},
	{Key: "netflix", Label: "Netflix", Domains: []string{"netflix.com", "nflxvideo.net", "nflximg.net", "nflxext.com"}},
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
	dnsRecords, err := app.FindAllRecords("dns_queries", dbx.HashExp{"session": sessionID})
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
			Confidence: attribution.GetString("confidence"), DNSQueryID: attribution.GetString("dns_query"),
		})
	}
	dns := make([]DNSObservation, 0, len(dnsRecords))
	for _, record := range dnsRecords {
		dns = append(dns, dnsObservationFromRecord(record))
	}

	episodes, associations := InferActivityAssociations(flows, dns)
	episodeIDs, err := syncActivityEpisodes(app, sessionID, episodes)
	if err != nil {
		return err
	}
	if err := syncFlowAssociations(app, sessionID, associations, episodeIDs); err != nil {
		return err
	}
	return removeStaleActivityEpisodes(app, sessionID, episodes)
}

func InferActivityAssociations(flows []AttributedFlowObservation, dns []DNSObservation) ([]ActivityEpisodeConclusion, []FlowAssociationConclusion) {
	sortedFlows := append([]AttributedFlowObservation(nil), flows...)
	sort.Slice(sortedFlows, func(i, j int) bool { return sortedFlows[i].Flow.Start.Before(sortedFlows[j].Flow.Start) })
	dnsByID := make(map[string]DNSObservation, len(dns))
	for _, observation := range dns {
		dnsByID[observation.ID] = observation
	}

	var episodes []ActivityEpisodeConclusion
	for _, family := range anchorSiteFamilies {
		byClient := make(map[string][]AttributedFlowObservation)
		for _, flow := range sortedFlows {
			if usableHostnameEvidence(flow) && familyMatchesHostname(family, flow.Hostname) {
				byClient[flow.Flow.ClientIP] = append(byClient[flow.Flow.ClientIP], flow)
			}
		}
		for clientIP, anchors := range byClient {
			var current *ActivityEpisodeConclusion
			for _, anchor := range anchors {
				if current == nil || anchor.Flow.Start.Sub(current.AnchorTimes[len(current.AnchorTimes)-1]) > activityEpisodeGap {
					episodes = append(episodes, ActivityEpisodeConclusion{
						SessionID: anchor.Flow.SessionID, ClientIP: clientIP, SiteKey: family.Key,
						Label: family.Label, AnchorHostname: normalizeActivityHostname(anchor.Hostname),
						Start: anchor.Flow.Start, LastSeen: flowEnd(anchor.Flow), Confidence: "high",
						Explanation: fmt.Sprintf("Started from DNS-attributed first-party traffic to %s.", normalizeActivityHostname(anchor.Hostname)),
						AnchorTimes: []time.Time{anchor.Flow.Start},
					})
					current = &episodes[len(episodes)-1]
					current.Key = episodeKey(*current)
				} else {
					current.AnchorTimes = append(current.AnchorTimes, anchor.Flow.Start)
					if end := flowEnd(anchor.Flow); end.After(current.LastSeen) {
						current.LastSeen = end
					}
				}
			}
		}
	}
	sort.Slice(episodes, func(i, j int) bool { return episodes[i].Start.Before(episodes[j].Start) })

	associations := make(map[string]FlowAssociationConclusion)
	for _, episode := range episodes {
		family, _ := familyByKey(episode.SiteKey)
		for _, flow := range sortedFlows {
			if flow.Flow.ClientIP != episode.ClientIP || !usableHostnameEvidence(flow) || !familyMatchesHostname(family, flow.Hostname) {
				continue
			}
			if !withinEpisodeAnchors(flow.Flow.Start, episode.AnchorTimes, activityEpisodeGap) {
				continue
			}
			relationship := "first_party"
			explanation := fmt.Sprintf("%s belongs to the confirmed %s site family.", normalizeActivityHostname(flow.Hostname), episode.Label)
			if query, ok := dnsByID[flow.DNSQueryID]; ok && hasExternalAlias(query, family) {
				relationship = "cname_related"
				explanation = fmt.Sprintf("A DNS CNAME chain connects %s to infrastructure serving the confirmed %s site family.", normalizeActivityHostname(flow.Hostname), episode.Label)
			}
			associations[flow.Flow.ID] = FlowAssociationConclusion{
				FlowID: flow.Flow.ID, EpisodeKey: episode.Key, ParentSiteKey: episode.SiteKey, ParentLabel: episode.Label,
				Relationship: relationship, Confidence: "high", Score: 100, Explanation: explanation, ObservedAt: flow.Flow.Start,
			}
		}
	}

	for _, candidate := range sortedFlows {
		if _, exists := associations[candidate.Flow.ID]; exists || !usableHostnameEvidence(candidate) || isKnownAnchorHostname(candidate.Hostname) {
			continue
		}
		query, hasDNS := dnsByID[candidate.DNSQueryID]
		if !hasDNS || normalizeActivityHostname(query.QueryName) != normalizeActivityHostname(candidate.Hostname) {
			continue
		}
		bestIndex, bestDistance, ambiguous := nearestEpisodeAnchor(episodes, candidate)
		if bestIndex < 0 || ambiguous {
			continue
		}
		episode := episodes[bestIndex]
		if hostnameSeenBefore(sortedFlows, candidate, episode.Start.Add(-dnsAssociationTolerance)) {
			continue
		}
		anchorTime := candidate.Flow.Start.Add(-bestDistance)
		if query.Timestamp.Before(anchorTime.Add(-dnsAssociationTolerance)) || query.Timestamp.After(candidate.Flow.Start.Add(dnsAssociationTolerance)) {
			continue
		}
		score := 85
		if bestDistance <= 3*time.Second {
			score += 10
		}
		if !flowEnd(candidate.Flow).Before(anchorTime) {
			score += 5
		}
		associations[candidate.Flow.ID] = FlowAssociationConclusion{
			FlowID: candidate.Flow.ID, EpisodeKey: episode.Key, ParentSiteKey: episode.SiteKey, ParentLabel: episode.Label,
			Relationship: "temporally_associated", Confidence: "medium", Score: score,
			Explanation: fmt.Sprintf("%s was freshly resolved by the same client and opened %s after confirmed %s traffic. This is an association, not proof that the site initiated it.", normalizeActivityHostname(candidate.Hostname), formatApproxDuration(bestDistance), episode.Label),
			ObservedAt:  candidate.Flow.Start,
		}
	}

	result := make([]FlowAssociationConclusion, 0, len(associations))
	for _, association := range associations {
		result = append(result, association)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ObservedAt.Before(result[j].ObservedAt) })
	return episodes, result
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

func familyMatchesHostname(family siteFamily, hostname string) bool {
	hostname = normalizeActivityHostname(hostname)
	for _, domain := range family.Domains {
		if hostname == domain || strings.HasSuffix(hostname, "."+domain) {
			return true
		}
	}
	return false
}

func isKnownAnchorHostname(hostname string) bool {
	for _, family := range anchorSiteFamilies {
		if familyMatchesHostname(family, hostname) {
			return true
		}
	}
	return false
}

func familyByKey(key string) (siteFamily, bool) {
	for _, family := range anchorSiteFamilies {
		if family.Key == key {
			return family, true
		}
	}
	return siteFamily{}, false
}

func normalizeActivityHostname(hostname string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(hostname)), ".")
}

func episodeKey(episode ActivityEpisodeConclusion) string {
	return fmt.Sprintf("%s|%s|%s|%d", episode.SessionID, episode.ClientIP, episode.SiteKey, episode.Start.Unix())
}

func withinEpisodeAnchors(at time.Time, anchors []time.Time, window time.Duration) bool {
	for _, anchor := range anchors {
		if distance := at.Sub(anchor); distance >= 0 && distance <= window {
			return true
		}
	}
	return false
}

func hasExternalAlias(query DNSObservation, family siteFamily) bool {
	for _, alias := range query.Aliases {
		if !familyMatchesHostname(family, alias) {
			return true
		}
	}
	return false
}

func hostnameSeenBefore(flows []AttributedFlowObservation, candidate AttributedFlowObservation, cutoff time.Time) bool {
	hostname := normalizeActivityHostname(candidate.Hostname)
	for _, flow := range flows {
		if flow.Flow.ID != candidate.Flow.ID && flow.Flow.ClientIP == candidate.Flow.ClientIP &&
			normalizeActivityHostname(flow.Hostname) == hostname && flow.Flow.Start.Before(cutoff) {
			return true
		}
	}
	return false
}

func nearestEpisodeAnchor(episodes []ActivityEpisodeConclusion, candidate AttributedFlowObservation) (int, time.Duration, bool) {
	bestIndex := -1
	bestDistance := temporalAssociationWindow + time.Second
	ambiguous := false
	for index, episode := range episodes {
		if episode.ClientIP != candidate.Flow.ClientIP {
			continue
		}
		for _, anchor := range episode.AnchorTimes {
			distance := candidate.Flow.Start.Sub(anchor)
			if distance < 0 || distance > temporalAssociationWindow {
				continue
			}
			if distance < bestDistance {
				bestIndex, bestDistance, ambiguous = index, distance, false
			} else if bestIndex >= 0 && distance == bestDistance && episodes[bestIndex].SiteKey != episode.SiteKey {
				ambiguous = true
			}
		}
	}
	return bestIndex, bestDistance, ambiguous
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
