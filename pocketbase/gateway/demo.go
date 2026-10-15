package gateway

import (
	"database/sql"
	"errors"
	"net/http"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
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
		rec, err := tx.FindFirstRecordByFilter("sessions", "demo=true && active=true")
		if errors.Is(err, sql.ErrNoRows) {
			c, err := tx.FindCollectionByNameOrId("sessions")
			if err != nil {
				return err
			}
			rec = core.NewRecord(c)
			rec.Set("demo", true)
			rec.Set("name", "Lab demo")
			rec.Set("started_ms", time.Now().UnixMilli())
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
			other.Set("ended_ms", time.Now().UnixMilli())
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

func (g *Runtime) registerDemoRoutes(r *router.Router[*core.RequestEvent]) {
	app := g.app
	r.GET("/api/infrareveal/demo", func(e *core.RequestEvent) error {
		g.maintenance.RLock()
		maintenance := g.maintenance.status
		g.maintenance.RUnlock()
		result := map[string]any{"serverNow": time.Now().UTC().Format(time.RFC3339), "enabled": g.config.Demo, "ssid": g.config.SSID, "maintenance": maintenance}
		if g.config.Demo {
			session, err := app.FindFirstRecordByFilter("sessions", "demo=true && active=true")
			if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return e.InternalServerError("Cannot load demo", err)
			}
			if err == nil {
				result["sessionId"] = session.Id
				result["retentionMinutes"] = int(sessionRetention(session) / time.Minute)
				result["observing"] = g.CurrentSessionID() == session.Id
				result["capture"] = session.Get("capture")
			}
		}
		return e.JSON(http.StatusOK, result)
	})
}
