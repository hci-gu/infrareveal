package routing

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"time"
)

// RetainSession runs inside the caller's traffic-retention transaction. Keep
// the last publication before the retained edge and its invalidation history.
func RetainSession(app core.App, session string, cutoff time.Time) error {
	params := dbx.Params{"s": session, "cut": cutoff.UnixMilli()}
	for _, statement := range []string{
		`DELETE FROM route_evidence WHERE session={:s} AND kind='path' AND NOT EXISTS (SELECT 1 FROM traffic_chunks t WHERE t.session=route_evidence.session AND t.network_epoch=route_evidence.network_epoch AND t.destination_ip=route_evidence.destination_ip AND t.protocol=route_evidence.protocol AND t.destination_port=route_evidence.destination_port)`,
		`DELETE FROM route_evidence WHERE session={:s} AND kind='path' AND available_ms < {:cut} AND EXISTS (SELECT 1 FROM route_evidence newer WHERE newer.session=route_evidence.session AND newer.kind='path' AND newer.network_epoch=route_evidence.network_epoch AND newer.binding_key=route_evidence.binding_key AND newer.available_ms < {:cut} AND (newer.available_ms>route_evidence.available_ms OR (newer.available_ms=route_evidence.available_ms AND newer.id>route_evidence.id)))`,
		`DELETE FROM route_evidence WHERE session={:s} AND kind='network_invalidated' AND NOT EXISTS (SELECT 1 FROM route_evidence path WHERE path.session=route_evidence.session AND path.kind='path' AND path.network_epoch=route_evidence.network_epoch)`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
			return err
		}
	}
	return nil
}

// Open recordings keep their lifetime charges. Other admissions survive the
// rolling quota/negative-learning window, even when their session was deleted.
func RetainShared(app core.App, now time.Time) error {
	_, err := app.DB().NewQuery(`DELETE FROM probe_runs WHERE admitted_ms < {:cut}
 AND cooldown_until_ms < {:now} AND pause_until_ms < {:now}
 AND NOT EXISTS (SELECT 1 FROM sessions s WHERE s.id=probe_runs.session AND s.active=true AND s.ephemeral=false)`).Bind(dbx.Params{"cut": now.Add(-networkHistory).UnixMilli(), "now": now.UnixMilli()}).Execute()
	return err
}
