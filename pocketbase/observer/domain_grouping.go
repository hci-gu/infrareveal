package observer

import (
	"fmt"
	"sort"
	"time"
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
