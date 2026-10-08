package observer

import (
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"time"
)

// RetainSession uses the caller's transaction; catalogue collection must precede
// it. Live flows and DNS supporting retained attribution remain available.
func RetainSession(app core.App, session string, cutoff time.Time) error {
	params := dbx.Params{"session": session, "cut": cutoff.UTC().Format("2006-01-02 15:04:05.000Z")}
	staleFlows := `SELECT id FROM flows WHERE session={:session} AND last_seen < {:cut}`
	for _, statement := range []string{
		`DELETE FROM flow_activity_chunks WHERE session={:session} AND (julianday(chunk_start)+chunk_ms/86400000.0 <= julianday({:cut}) OR flow IN (` + staleFlows + `))`,
		`DELETE FROM flow_activity_windows WHERE session={:session} AND julianday(window_start)+window_ms/86400000.0 <= julianday({:cut})`,
		`DELETE FROM flow_associations WHERE session={:session} AND flow IN (` + staleFlows + `)`,
		`DELETE FROM flow_attributions WHERE session={:session} AND flow IN (` + staleFlows + `)`,
		`DELETE FROM flows WHERE session={:session} AND last_seen < {:cut}`,
		`DELETE FROM activity_episodes WHERE session={:session} AND NOT EXISTS (SELECT 1 FROM flow_associations WHERE episode=activity_episodes.id) AND last_seen < {:cut}`,
		`DELETE FROM dns_queries WHERE session={:session} AND timestamp < {:cut} AND NOT EXISTS (SELECT 1 FROM flow_attributions WHERE dns_query=dns_queries.id)`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(params).Execute(); err != nil {
			return err
		}
	}
	return nil
}
func RetainShared(app core.App, cutoff time.Time) error {
	for _, statement := range []string{
		`DELETE FROM destinations WHERE last_seen < {:cut} AND NOT EXISTS (SELECT 1 FROM flows WHERE destination_ip=destinations.ip) AND NOT EXISTS (SELECT 1 FROM routes WHERE destination=destinations.id OR destination_ip=destinations.ip)`,
		`DELETE FROM clients WHERE last_seen < {:cut} AND NOT EXISTS (SELECT 1 FROM flows WHERE client_ip=clients.ip)`,
	} {
		if _, err := app.DB().NewQuery(statement).Bind(dbx.Params{"cut": cutoff.UTC().Format("2006-01-02 15:04:05.000Z")}).Execute(); err != nil {
			return err
		}
	}
	return nil
}
