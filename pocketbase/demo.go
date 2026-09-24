package main

import (
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strconv"
	"sync"
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

var demoMaintenance struct {
	sync.RWMutex
	status demoMaintenanceStatus
}

func updateDemoMaintenance(now time.Time, err error) {
	demoMaintenance.Lock()
	defer demoMaintenance.Unlock()
	if err != nil {
		demoMaintenance.status.LastError = err.Error()
		return
	}
	demoMaintenance.status.LastSuccess = now.Format(time.RFC3339)
	demoMaintenance.status.LastError = ""
}

func demoEnabled() bool { return os.Getenv("DEMO_MODE") == "true" }

func ensureDemoSession(app core.App) error {
	minutes, err := strconv.Atoi(envOrDefault("DEMO_RETENTION_MINUTES", "30"))
	if err != nil || minutes < 1 || minutes > 1440 {
		return fmt.Errorf("DEMO_RETENTION_MINUTES must be an integer from 1 to 1440")
	}
	var id string
	err = app.RunInTransaction(func(tx core.App) error {
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
		activeSessionID.Store(&id)
	}
	return err
}

func collectDemoDomains(app core.App, session *core.Record) error {
	if !demoEnabled() || !session.GetBool("demo") || envOrDefault("DEMO_DOMAIN_CATALOGUE", "true") != "true" {
		return nil
	}
	return observer.CollectDomainCatalogue(app, session.Id)
}

func registerDemoRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	r.GET("/api/infrareveal/demo", func(e *core.RequestEvent) error {
		demoMaintenance.RLock()
		maintenance := demoMaintenance.status
		demoMaintenance.RUnlock()
		result := map[string]any{"serverNow": time.Now().UTC().Format(time.RFC3339), "enabled": demoEnabled(), "ssid": envOrDefault("SSID", "Infrareveal"), "maintenance": maintenance, "catalogueEnabled": demoEnabled() && envOrDefault("DEMO_DOMAIN_CATALOGUE", "true") == "true"}
		if demoEnabled() {
			session, err := app.FindFirstRecordByFilter("sessions", "demo=true && active=true")
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return e.InternalServerError("Cannot load demo", err)
			}
			if err == nil {
				result["sessionId"] = session.Id
				result["retentionMinutes"] = int(sessionRetention(session) / time.Minute)
				result["observing"] = currentSessionID() == session.Id
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
		return e.JSON(http.StatusOK, map[string]any{"version": 1, "exportedAt": time.Now().UTC().Format(time.RFC3339), "domains": exportRecords(rows)})
	}).Bind(apis.RequireSuperuserAuth())
}
