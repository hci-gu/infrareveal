package routing

import (
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// RetainSession runs in the caller's session-cleanup transaction, after expired
// flows have been removed. It preserves the latest pre-window route and event
// anchors required by retained flows. It never opens an independent transaction.
func RetainSession(app core.App, session string, cutoff time.Time) error {
	params := dbx.Params{"session": session, "cut": recordDate(cutoff)}
	for _, statement := range []string{
		`DELETE FROM routes WHERE session={:session} AND NOT EXISTS (SELECT 1 FROM flows WHERE flows.session=routes.session AND flows.destination_ip=routes.destination_ip AND flows.destination_port=routes.destination_port AND flows.protocol=routes.protocol)`,
		// Keep the last pre-window revision as an anchor for long-lived flows.
		`DELETE FROM routes WHERE session={:session} AND COALESCE(NULLIF(available_at,''),completed_at) < {:cut} AND EXISTS (SELECT 1 FROM routes newer WHERE newer.session=routes.session AND newer.destination_ip=routes.destination_ip AND newer.destination_port=routes.destination_port AND newer.protocol=routes.protocol AND COALESCE(NULLIF(newer.available_at,''),newer.completed_at) < {:cut} AND (COALESCE(NULLIF(newer.available_at,''),newer.completed_at) > COALESCE(NULLIF(routes.available_at,''),routes.completed_at) OR (COALESCE(NULLIF(newer.available_at,''),newer.completed_at)=COALESCE(NULLIF(routes.available_at,''),routes.completed_at) AND newer.id > routes.id)))`,
		`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND kind != 'network_invalidated' AND NOT EXISTS (SELECT 1 FROM routes WHERE routes.id=route_evidence_updates.binding_key)`,
		`DELETE FROM route_outcomes WHERE session={:session} AND available_at < {:cut}`,
		`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND kind='network_invalidated' AND NOT EXISTS (SELECT 1 FROM routes WHERE routes.session=route_evidence_updates.session AND routes.network_context=route_evidence_updates.network_context)`,
		`DELETE FROM route_evidence_updates WHERE session={:session} AND available_at < {:cut} AND EXISTS (SELECT 1 FROM route_evidence_updates newer WHERE newer.session=route_evidence_updates.session AND newer.kind=route_evidence_updates.kind AND newer.binding_key=route_evidence_updates.binding_key AND newer.network_context=route_evidence_updates.network_context AND newer.available_at < {:cut} AND (newer.available_at > route_evidence_updates.available_at OR (newer.available_at=route_evidence_updates.available_at AND newer.id > route_evidence_updates.id)))`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
			return err
		}
	}
	return nil
}

// RetainShared keeps cache and suppression lifetimes independent of the session
// window. The gateway calls this even when discovery is disabled; observations
// referenced by any recording are always retained.
func RetainShared(app core.App, observationCutoff, cacheCutoff time.Time) error {
	params := dbx.Params{"cut": recordDate(observationCutoff), "cacheCut": recordDate(cacheCutoff)}
	for _, statement := range []string{
		`DELETE FROM route_cache WHERE id IN (SELECT id FROM route_cache ORDER BY last_used_at DESC LIMIT -1 OFFSET 1000) OR last_used_at < {:cacheCut}`,
		`DELETE FROM route_budget_state WHERE (key LIKE 'negative:%' OR key LIKE 'network:%') AND julianday(available_at) < julianday({:cacheCut})`,
		`DELETE FROM route_observations WHERE julianday(measured_at) < julianday({:cut}) AND NOT EXISTS (SELECT 1 FROM routes WHERE observation_id=route_observations.id)`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
			return err
		}
	}
	return nil
}
