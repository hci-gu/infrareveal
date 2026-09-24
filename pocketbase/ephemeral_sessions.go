package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

const ephemeralWindow = 5 * time.Minute

// Keep the original creation date for identity; started_at is the retained edge.
func normalizeEphemeralSession(record *core.Record, now time.Time) {
	if !record.GetBool("ephemeral") {
		return
	}
	record.Set("active", true)
	record.Set("ended_at", "")
	if record.GetDateTime("started_at").IsZero() {
		record.Set("started_at", now)
	} else if record.GetDateTime("started_at").Time().Before(now.Add(-ephemeralWindow)) {
		record.Set("started_at", now.Add(-ephemeralWindow))
	}
}

func startEphemeralRetention(ctx context.Context, app core.App) {
	go func() {
		ticker := time.NewTicker(15 * time.Second)
		defer ticker.Stop()
		for {
			if err := pruneEphemeralSessions(app, time.Now().UTC()); err != nil {
				log.Printf("ephemeral retention: %v", err)
			}

			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

// Set-based deletion intentionally avoids per-row SSE storms. The browser owns
// age-based eviction, including while disconnected. SQLite reuses freed pages.
// Short transactions serialize against observer writes. No ordinary session rows
// are deleted; shared destination evidence is retained while any flow/route uses it.
func pruneEphemeralSessions(app core.App, now time.Time) error {
	sessions, err := app.FindRecordsByFilter("sessions", "ephemeral=true", "", 0, 0)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		err = app.RunInTransaction(func(tx core.App) error {
			// A settings edit may have disabled retention since the outer query.
			current, err := tx.FindRecordById("sessions", session.Id)
			if err != nil {
				return err
			}
			if !current.GetBool("ephemeral") {
				return nil
			}
			params := dbx.Params{"session": session.Id, "cut": formatPocketBaseTimelineDate(now.Add(-ephemeralWindow))}
			staleFlows := `SELECT id FROM flows WHERE session={:session} AND last_seen < {:cut}`
			statements := []string{
				`DELETE FROM flow_activity_chunks WHERE session={:session} AND (julianday(chunk_start)+chunk_ms/86400000.0 <= julianday({:cut}) OR flow IN (` + staleFlows + `))`,
				`DELETE FROM flow_activity_windows WHERE session={:session} AND julianday(window_start)+window_ms/86400000.0 <= julianday({:cut})`,
				`DELETE FROM gate_events WHERE session={:session} AND queued_at < {:cut} AND state != 'queued'`,
				`DELETE FROM flow_associations WHERE session={:session} AND flow IN (` + staleFlows + `)`,
				`DELETE FROM flow_attributions WHERE session={:session} AND flow IN (` + staleFlows + `)`,
				`DELETE FROM flows WHERE session={:session} AND last_seen < {:cut}`,
				`DELETE FROM activity_episodes WHERE session={:session} AND NOT EXISTS (SELECT 1 FROM flow_associations WHERE episode=activity_episodes.id) AND last_seen < {:cut}`,
				// Preserve DNS supporting a still-retained attribution. This is at most a
				// bounded dependency set, not five minutes of unrelated DNS every sweep.
				`DELETE FROM dns_queries WHERE session={:session} AND timestamp < {:cut} AND NOT EXISTS (SELECT 1 FROM flow_attributions WHERE dns_query=dns_queries.id)`,
				`DELETE FROM routes WHERE session={:session} AND NOT EXISTS (SELECT 1 FROM flows WHERE flows.session=routes.session AND flows.destination_ip=routes.destination_ip AND flows.destination_port=routes.destination_port AND flows.protocol=routes.protocol)`,
				// Keep the last pre-window revision as an anchor for long-lived flows.
				`DELETE FROM routes WHERE session={:session} AND COALESCE(NULLIF(available_at,''),completed_at) < {:cut} AND EXISTS (SELECT 1 FROM routes newer WHERE newer.session=routes.session AND newer.destination_ip=routes.destination_ip AND newer.destination_port=routes.destination_port AND newer.protocol=routes.protocol AND COALESCE(NULLIF(newer.available_at,''),newer.completed_at) < {:cut} AND (COALESCE(NULLIF(newer.available_at,''),newer.completed_at) > COALESCE(NULLIF(routes.available_at,''),routes.completed_at) OR (COALESCE(NULLIF(newer.available_at,''),newer.completed_at)=COALESCE(NULLIF(routes.available_at,''),routes.completed_at) AND newer.id > routes.id)))`,
				`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND kind != 'network_invalidated' AND NOT EXISTS (SELECT 1 FROM routes WHERE routes.id=route_evidence_updates.binding_key)`,
				`DELETE FROM route_outcomes WHERE session={:session} AND available_at < {:cut}`,
				`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND kind='network_invalidated' AND NOT EXISTS (SELECT 1 FROM routes WHERE routes.session=route_evidence_updates.session AND routes.network_context=route_evidence_updates.network_context)`,
				`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND EXISTS (SELECT 1 FROM route_evidence_updates newer WHERE newer.session=route_evidence_updates.session AND newer.kind=route_evidence_updates.kind AND newer.binding_key=route_evidence_updates.binding_key AND newer.network_context=route_evidence_updates.network_context AND newer.available_at < {:cut} AND (newer.available_at > route_evidence_updates.available_at OR (newer.available_at=route_evidence_updates.available_at AND newer.id > route_evidence_updates.id)))`,
				`UPDATE sessions SET active=true, ended_at='', started_at=CASE WHEN started_at < {:cut} OR started_at='' THEN {:cut} ELSE started_at END WHERE id={:session}`,
			}
			for _, statement := range statements {
				if _, err := tx.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
					return fmt.Errorf("session %s: %w", session.Id, err)
				}
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	if len(sessions) == 0 {
		return nil
	}
	// Shared caches are bounded independently, even when route probing is disabled.
	params := dbx.Params{"cut": formatPocketBaseTimelineDate(now.Add(-ephemeralWindow)), "day": formatPocketBaseTimelineDate(now.Add(-24 * time.Hour))}
	for _, statement := range []string{
		`DELETE FROM destinations WHERE last_seen < {:cut} AND NOT EXISTS (SELECT 1 FROM flows WHERE destination_ip=destinations.ip) AND NOT EXISTS (SELECT 1 FROM routes WHERE destination=destinations.id OR destination_ip=destinations.ip)`,
		`DELETE FROM clients WHERE last_seen < {:cut} AND NOT EXISTS (SELECT 1 FROM flows WHERE client_ip=clients.ip)`,
		`DELETE FROM route_observations WHERE measured_at < {:cut} AND NOT EXISTS (SELECT 1 FROM routes WHERE observation_id=route_observations.id)`,
		`DELETE FROM route_cache WHERE last_used_at < {:day} OR id IN (SELECT id FROM route_cache ORDER BY last_used_at DESC LIMIT -1 OFFSET 1000)`,
		`DELETE FROM route_budget_state WHERE (key LIKE 'negative:%' OR key LIKE 'network:%') AND available_at < {:day}`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
			return err
		}
	}
	return nil
}
