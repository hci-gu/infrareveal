package gateway

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/observer"
)

type demoMaintenanceStatus struct {
	LastSuccess string `json:"lastSuccess"`
	LastError   string `json:"lastError"`
}

func (g *Runtime) updateDemoMaintenance(now time.Time, err error) {
	g.maintenance.Lock()
	defer g.maintenance.Unlock()
	if err != nil {
		g.maintenance.status.LastError = err.Error()
		return
	}
	g.maintenance.status.LastSuccess = now.Format(time.RFC3339)
	g.maintenance.status.LastError = ""
}

func (g *Runtime) ensureDemoSession() error {
	app := g.app
	minutes := g.config.DemoRetentionMinutes
	var id string
	err := app.RunInTransaction(func(tx core.App) error {
		rec, err := tx.FindFirstRecordByFilter("sessions", "demo=true")
		if errors.Is(err, sql.ErrNoRows) {
			c, err := tx.FindCollectionByNameOrId("sessions")
			if err != nil {
				return err
			}
			rec = core.NewRecord(c)
			rec.Set("demo", true)
			rec.Set("name", "Lab demo")
			rec.Set("started_at", time.Now().UTC())
		} else if err != nil {
			return err
		}
		others, err := tx.FindRecordsByFilter("sessions", "active=true && demo=false", "", 0, 0)
		if err != nil {
			return err
		}
		for _, other := range others {
			other.Set("ephemeral", false)
			other.Set("active", false)
			other.Set("ended_at", time.Now().UTC())
			if err = tx.Save(other); err != nil {
				return err
			}
		}
		rec.Set("active", true)
		rec.Set("ephemeral", true)
		rec.Set("retention_minutes", minutes)
		normalizeEphemeralSession(rec, time.Now().UTC())
		if err = tx.Save(rec); err != nil {
			return err
		}
		id = rec.Id
		return nil
	})
	if err == nil {
		g.activeSessionID.Store(&id)
	}
	return err
}

func (g *Runtime) collectDemoDomains(app core.App, session *core.Record) error {
	if !g.config.Demo || !session.GetBool("demo") || !g.config.DomainCatalogue {
		return nil
	}
	return observer.CollectDomainCatalogue(app, session.Id)
}

func (g *Runtime) registerDemoRoutes(r *router.Router[*core.RequestEvent]) {
	app := g.app
	r.GET("/api/infrareveal/demo", func(e *core.RequestEvent) error {
		g.maintenance.RLock()
		maintenance := g.maintenance.status
		g.maintenance.RUnlock()
		result := map[string]any{"serverNow": time.Now().UTC().Format(time.RFC3339), "enabled": g.config.Demo, "ssid": g.config.SSID, "maintenance": maintenance, "catalogueEnabled": g.config.Demo && g.config.DomainCatalogue}
		if g.config.Demo {
			session, err := app.FindFirstRecordByFilter("sessions", "demo=true && active=true")
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return e.InternalServerError("Cannot load demo", err)
			}
			if err == nil {
				result["sessionId"] = session.Id
				result["retentionMinutes"] = int(sessionRetention(session) / time.Minute)
				result["observing"] = g.CurrentSessionID() == session.Id
				status, err := app.FindFirstRecordByFilter("flow_activity_status", "session={:s}", dbx.Params{"s": session.Id})
				if err == nil {
					result["capture"] = map[string]any{"running": status.GetBool("running"), "reportedAt": status.GetString("reported_at"), "lastError": status.GetString("last_error")}
				}
			}
		}
		return e.JSON(http.StatusOK, result)
	})
	r.GET("/api/infrareveal/domain-catalogue/export", func(e *core.RequestEvent) error {
		rows, err := app.FindRecordsByFilter("domain_catalogue", "", "domain", 0, 0)
		if err != nil {
			return e.InternalServerError("Cannot export catalogue", err)
		}
		e.Response.Header().Set("Content-Disposition", `attachment; filename="domain-catalogue.json"`)
		return e.JSON(http.StatusOK, map[string]any{"version": 1, "exportedAt": time.Now().UTC().Format(time.RFC3339), "domains": exportCatalogueRecords(rows)})
	}).Bind(apis.RequireSuperuserAuth())
}

func exportCatalogueRecords(rows []*core.Record) []map[string]any {
	result := make([]map[string]any, 0, len(rows))
	for _, row := range rows {
		result = append(result, row.PublicExport())
	}
	return result
}
