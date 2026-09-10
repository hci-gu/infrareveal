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
