package observer

import (
	"reflect"
	"testing"
	"time"
)

func TestInferActivityAssociationsGroupsEveryDomain(t *testing.T) {
	start := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	flows := []AttributedFlowObservation{
		activityFlow("spotify", "api.spotify.com", start),
		activityFlow("discord", "discord.com", start),
		activityFlow("gateway", "gateway.discord.gg", start.Add(8*time.Second)),
		activityFlow("discord-cdn", "cdn.discordapp.com", start.Add(time.Hour)),
		activityFlow("chat", "chatgpt.com", start),
		activityFlow("chat-cdn", "cdn.oaistatic.com", start.Add(2*time.Hour)),
		activityFlow("facebook", "scontent-arn2-1.xx.fbcdn.net", start),
		activityFlow("svt", "www.svt.se", start),
		activityFlow("unknown", "api.new-service.co.uk", start),
		activityFlow("google", "clients3.google.com", start),
	}
	episodes, associations := InferActivityAssociations(flows)
	byFlow := associationsByFlow(associations)
	want := map[string]string{"spotify": "spotify.com", "discord": "discord.com", "gateway": "discord.com", "discord-cdn": "discord.com", "chat": "chatgpt.com", "chat-cdn": "chatgpt.com", "facebook": "facebook.com", "svt": "svt.se", "unknown": "new-service.co.uk", "google": "google.com"}
	for id, domain := range want {
		if got := byFlow[id].ParentSiteKey; got != domain {
			t.Errorf("%s: got %q, want %q", id, got, domain)
		}
	}
	if len(episodes) != 7 {
		t.Errorf("got %d groups, want 7", len(episodes))
	}
	if byFlow["gateway"].Relationship != "domain_alias" {
		t.Errorf("expected explicit domain alias: %#v", byFlow["gateway"])
	}
	if byFlow["discord"].EpisodeKey != byFlow["discord-cdn"].EpisodeKey {
		t.Error("time gaps must not split a domain group")
	}
	// Sorting and stable group keys must not depend on input order or the earliest flow.
	for i, j := 0, len(flows)-1; i < j; i, j = i+1, j-1 {
		flows[i], flows[j] = flows[j], flows[i]
	}
	again, links := InferActivityAssociations(flows)
	if !reflect.DeepEqual(episodes, again) || !reflect.DeepEqual(associations, links) {
		t.Error("grouping depends on input order")
	}
	_, single := InferActivityAssociations([]AttributedFlowObservation{activityFlow("discord-cdn", "cdn.discordapp.com", start.Add(time.Hour))})
	if len(single) != 1 {
		t.Fatalf("expected one domain association, got %d", len(single))
	}
	if single[0].EpisodeKey != byFlow["discord-cdn"].EpisodeKey {
		t.Error("group identity depends on first observation")
	}
}

func TestInferActivityAssociationsSeparatesClientsSessionsAndUnknownTraffic(t *testing.T) {
	start := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	first := activityFlow("first", "api.example.com", start)
	otherClient := activityFlow("client", "example.com", start)
	otherClient.Flow.ClientIP = "10.0.0.61"
	otherSession := activityFlow("session", "example.com", start)
	otherSession.Flow.SessionID = "another-session"
	flows := []AttributedFlowObservation{first, otherClient, otherSession}
	for i, hostname := range []string{"", "192.0.2.1", "::1", "localhost", "co.uk", "bad..com"} {
		flows = append(flows, activityFlow(string(rune('a'+i)), hostname, start))
	}
	low := activityFlow("low", "example.com", start)
	low.Confidence = "low"
	hidden := activityFlow("hidden", "example.com", start)
	hidden.Confidence = "hidden"
	flows = append(flows, low, hidden)
	episodes, associations := InferActivityAssociations(flows)
	if len(episodes) != 3 || len(associations) != 3 {
		t.Fatalf("expected 3 isolated groups and links, got %d/%d", len(episodes), len(associations))
	}
}

func activityFlow(id, hostname string, start time.Time) AttributedFlowObservation {
	return AttributedFlowObservation{
		Flow: FlowObservation{
			ID: id, SessionID: "session", ClientIP: "10.0.0.50", DestinationIP: "93.184.216.34",
			DestinationPort: 443, Protocol: "tcp", Start: start, LastSeen: start.Add(3 * time.Second),
		},
		Hostname: hostname, Confidence: "medium",
	}
}

func associationsByFlow(associations []FlowAssociationConclusion) map[string]FlowAssociationConclusion {
	result := make(map[string]FlowAssociationConclusion, len(associations))
	for _, association := range associations {
		result[association.FlowID] = association
	}
	return result
}

// Exercise the live correlator's storage seam: replace an existing temporal
// association, remove its stale group, and keep IDs stable on the next tick.
func TestCorrelateActivitySessionReplacesTemporalGroups(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	record := createActivityTestFlow(t, app, session.Id, "tcp|10.0.0.50|53000|93.184.216.34|443")
	flow := flowObservationFromRecord(record)
	_, err := upsertAttribution(app, flow, AttributionConclusion{CandidateHostname: "gateway.discord.gg", SourceSignal: "dns_answer", Confidence: "medium", ObservedAt: flow.Start})
	if err != nil {
		t.Fatal(err)
	}
	old := ActivityEpisodeConclusion{Key: "old-timing-group", SessionID: session.Id, ClientIP: flow.ClientIP, SiteKey: "spotify", Label: "Spotify", AnchorHostname: "api.spotify.com", Start: flow.Start, LastSeen: flow.Start, Confidence: "high"}
	ids, err := syncActivityEpisodes(app, session.Id, []ActivityEpisodeConclusion{old})
	if err != nil {
		t.Fatal(err)
	}
	err = syncFlowAssociations(app, session.Id, []FlowAssociationConclusion{{FlowID: flow.ID, EpisodeKey: old.Key, ParentSiteKey: "spotify", ParentLabel: "Spotify", Relationship: "temporally_associated", Confidence: "medium", Score: 90, ObservedAt: flow.Start}}, ids)
	if err != nil {
		t.Fatal(err)
	}
	var groupID, linkID string
	for tick := 0; tick < 2; tick++ {
		if err := correlateActivitySession(app, session.Id); err != nil {
			t.Fatal(err)
		}
		groups, err := app.FindAllRecords("activity_episodes")
		if err != nil || len(groups) != 1 {
			t.Fatalf("groups: count=%d err=%v", len(groups), err)
		}
		links, err := app.FindAllRecords("flow_associations")
		if err != nil || len(links) != 1 {
			t.Fatalf("links: count=%d err=%v", len(links), err)
		}
		if groups[0].GetString("site_key") != "discord.com" || links[0].GetString("relationship") != "domain_alias" || links[0].GetString("episode") != groups[0].Id {
			t.Fatal("old temporal grouping was not replaced")
		}
		if tick > 0 && (groupID != groups[0].Id || linkID != links[0].Id) {
			t.Fatal("IDs changed on repeated correlation")
		}
		groupID, linkID = groups[0].Id, links[0].Id
	}
}

func TestInferActivityAssociationsExactHostnameOverride(t *testing.T) {
	start := time.Date(2026, 9, 17, 10, 0, 0, 0, time.UTC)
	cases := map[string]string{
		"ios.chat.openai.com":             "chatgpt.com",
		" IOS.CHAT.OPENAI.COM. ":          "chatgpt.com",
		"api.openai.com":                  "openai.com",
		"chat.openai.com":                 "openai.com",
		"other.ios.chat.openai.com":       "openai.com",
		"ios.chat.openai.com.example.org": "example.org",
	}
	for hostname, want := range cases {
		t.Run(hostname, func(t *testing.T) {
			_, links := InferActivityAssociations([]AttributedFlowObservation{activityFlow("flow", hostname, start)})
			if len(links) != 1 || links[0].ParentSiteKey != want {
				t.Fatalf("got %#v; want %s", links, want)
			}
		})
	}
}
