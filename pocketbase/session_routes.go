package main

import (
	"encoding/json"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"time"
)

// Route pagination is independent of flow pagination. Otherwise a long probe
// history vanishes after the flow page reaches its end cursor.
func queryRouteRevisions(app core.App, session string, from, to time.Time, flowIDs []string, overview bool, limit, offset int) ([]*core.Record, bool, error) {
	ids, _ := json.Marshal(flowIDs)
	at := `COALESCE(NULLIF(routes.available_at,''),routes.completed_at)`
	newerAt := `COALESCE(NULLIF(newer.available_at,''),newer.completed_at)`
	cutoff := from
	if overview {
		cutoff = to
	}
	params := dbx.Params{"routeSession": session, "routeFrom": formatPocketBaseTimelineDate(from), "routeTo": formatPocketBaseTimelineDate(to), "routeCutoff": formatPocketBaseTimelineDate(cutoff), "routeFlowIDs": string(ids), "routeAllFlows": len(flowIDs) == 0}
	latest := `NOT EXISTS (SELECT 1 FROM routes newer WHERE newer.session=routes.session AND newer.destination_ip=routes.destination_ip AND newer.destination_port=routes.destination_port AND newer.protocol=routes.protocol AND ` + newerAt + ` < {:routeCutoff} AND (` + newerAt + ` > ` + at + ` OR (` + newerAt + ` = ` + at + ` AND newer.id > routes.id)))`
	period := `(` + at + ` < {:routeFrom} AND ` + latest + `) OR (` + at + ` >= {:routeFrom} AND ` + at + ` < {:routeTo})`
	if overview {
		period = at + ` < {:routeTo} AND ` + latest
	}
	scope := `routes.session={:routeSession} AND EXISTS (SELECT 1 FROM flows f WHERE f.session=routes.session AND f.destination_ip=routes.destination_ip AND f.destination_port=routes.destination_port AND f.protocol=routes.protocol AND f.start < {:routeTo} AND ({:routeAllFlows} OR f.id IN (SELECT value FROM json_each({:routeFlowIDs})))) AND (` + period + `)`
	return queryTimelinePage(app, "routes", []dbx.Expression{dbx.NewExp(scope, params)}, []string{at, "id"}, limit, offset)
}

// Attach small evidence events to immutable snapshots at read time. The browser
// applies them at the playback cursor, never at the time this request completed.
func exportRouteRecords(app core.App, records []*core.Record, to time.Time) ([]map[string]any, error) {
	result := exportRecords(records)
	sessions := map[string][]*core.Record{}
	for _, r := range records {
		s := r.GetString("session")
		if _, ok := sessions[s]; ok {
			continue
		}
		events, err := app.FindRecordsByFilter("route_evidence_updates", "session={:s} && available_at <= {:to}", "available_at", 0, 0, dbx.Params{"s": s, "to": formatPocketBaseTimelineDate(to)})
		if err != nil {
			return nil, err
		}
		sessions[s] = events
	}
	for i, r := range records {
		updates := []map[string]any{}
		for _, event := range sessions[r.GetString("session")] {
			if event.GetString("binding_key") == r.Id || (event.GetString("kind") == "network_invalidated" && event.GetString("network_context") == r.GetString("network_context") && event.GetDateTime("available_at").Time().After(r.GetDateTime("available_at").Time())) {
				updates = append(updates, map[string]any{"kind": event.GetString("kind"), "available_at": event.GetString("available_at"), "value": event.Get("value")})
			}
		}
		result[i]["evidence_updates"] = updates
	}
	// Only byte-equivalent legacy evidence with identical temporal metadata can
	// coalesce. Distinct confirmation/availability transitions remain intact.
	seen := map[string]bool{}
	coalesced := make([]map[string]any, 0, len(result))
	for _, row := range result {
		value := map[string]any{}
		for k, v := range row {
			if k != "id" && k != "created" && k != "updated" {
				value[k] = v
			}
		}
		encoded, err := json.Marshal(value)
		if err != nil {
			return nil, err
		}
		key := string(encoded)
		if !seen[key] {
			coalesced = append(coalesced, row)
			seen[key] = true
		}
	}
	return coalesced, nil
}
