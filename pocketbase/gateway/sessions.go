package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/data"
	"myapp/labgate"
	"myapp/observer"
)

func (g *Runtime) registerSessionHooks() {
	g.app.OnRecordDeleteRequest("sessions").BindFunc(func(e *core.RecordRequestEvent) error {
		if e.Get(core.RequestEventKeyInfoContext) != core.RequestInfoContextBatch {
			if _, _, err := g.drainSessionGate(e.Request.Context(), e.Record.Id); err != nil {
				return err
			}
		}
		return e.Next()
	})
	g.app.OnRecordCreate("sessions").BindFunc(func(e *core.RecordEvent) error {
		if err := g.prepareSession(e.Record, nil); err != nil {
			return err
		}
		e.Record.Set("gate_audit_complete", true)
		return e.Next()
	})
	g.app.OnRecordUpdate("sessions").BindFunc(func(e *core.RecordEvent) error {
		return e.App.RunInTransaction(func(tx core.App) error {
			current, err := tx.FindRecordById("sessions", e.Record.Id)
			if err != nil {
				return err
			}
			if err := g.prepareSession(e.Record, current); err != nil {
				return err
			}
			e.App = tx
			return e.Next()
		})
	})
	installed := func(e *core.RecordEvent) error {
		wasActive := g.CurrentSessionID() == e.Record.Id || e.Record.Original().GetBool("active")
		if e.Record.GetBool("active") {
			id := e.Record.Id
			g.activeSessionID.Store(&id)
		} else if g.CurrentSessionID() == e.Record.Id {
			g.activeSessionID.Store(nil)
		}
		if !e.Record.GetBool("active") && wasActive {
			if err := g.finishSession(e.Record); err != nil {
				return err
			}
		}
		return e.Next()
	}
	g.app.OnRecordAfterCreateSuccess("sessions").BindFunc(installed)
	g.app.OnRecordAfterUpdateSuccess("sessions").BindFunc(installed)
	g.app.OnRecordDelete("sessions").BindFunc(func(e *core.RecordEvent) error {
		return e.App.RunInTransaction(func(tx core.App) error {
			if err := deleteSessionData(tx, e.Record.Id); err != nil {
				return err
			}
			e.App = tx
			return e.Next()
		})
	})
	g.app.OnRecordAfterDeleteSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
		if g.CurrentSessionID() == e.Record.Id {
			g.activeSessionID.Store(nil)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := g.drainSessionGate(ctx, e.Record.Id); err != nil {
			return err
		}
		// Batch deletion can only drain audit after its outer transaction commits.
		if _, err := g.app.FindCollectionByNameOrId("gate_events"); err == nil {
			if _, err = g.app.DB().NewQuery("DELETE FROM gate_events WHERE session={:id}").Bind(dbx.Params{"id": e.Record.Id}).Execute(); err != nil {
				return err
			}
		}
		return e.Next()
	})
}

func (g *Runtime) prepareSession(record, original *core.Record) error {
	now := time.Now().UnixMilli()
	if original != nil && original.GetInt64("ended_ms") > 0 && record.GetBool("active") {
		return fmt.Errorf("closed sessions cannot be reopened")
	}
	if g.config.Demo && record.GetBool("active") && !record.GetBool("demo") {
		return fmt.Errorf("disable DEMO_MODE before starting another session")
	}
	revision := int64(1)
	if original == nil {
		if record.GetInt64("started_ms") == 0 {
			record.Set("started_ms", now)
		}
		if record.GetInt("retention_minutes") == 0 {
			record.Set("retention_minutes", 30)
		}
		policy := observer.DefaultPolicy()
		// Packet samples use globally aligned source bins. Starting inside a
		// bin must not discard the first accepted packets in that bin.
		start := record.GetInt64("started_ms") / policy.BucketMS * policy.BucketMS
		record.Set("started_ms", start)
		record.Set("retained_from_ms", start)
		record.Set("block_watermark_ms", start)
		record.Set("policy", policy)
		record.Set("diagnostics", data.Diagnostics{Flows: g.config.Diagnostics, DNS: g.config.Diagnostics, Gate: g.config.Diagnostics || g.config.Gate.Enabled})
	} else {
		for _, field := range []string{"started_ms", "ended_ms", "retained_from_ms", "block_watermark_ms", "policy", "diagnostics", "capture", "network_context", "network_epoch"} {
			record.Set(field, original.Get(field))
		}
		revision = original.GetInt64("revision") + 1
	}
	if minutes := record.GetInt("retention_minutes"); minutes < 1 || minutes > 1440 {
		return fmt.Errorf("retention_minutes must be 1–1440")
	}
	if strings.TrimSpace(record.GetString("name")) == "" {
		record.Set("name", "Gateway Session")
	}
	if record.GetBool("active") {
		record.Set("ended_ms", 0)
	} else if record.GetInt64("ended_ms") == 0 {
		record.Set("ended_ms", now)
	}
	if original == nil {
		normalizeEphemeralSession(record, time.UnixMilli(now))
	}
	record.Set("revision", revision)
	return nil
}

func (g *Runtime) finishSession(record *core.Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	complete, drops, flushErr := g.drainSessionGate(ctx, record.Id)
	// The observer has drained before the lifecycle commit. Project once with
	// the durable end so the endpoint immediately publishes final block flags.
	projectionErr := observer.RebuildBlocks(g.app, record.Id, time.Now().UnixMilli())
	if g.audit == nil && flushErr == nil {
		return projectionErr
	}
	saveErr := g.app.RunInTransaction(func(tx core.App) error {
		current, err := tx.FindRecordById("sessions", record.Id)
		if err != nil {
			return err
		}
		if current.GetBool("active") {
			return nil
		}
		current.Set("gate_audit_complete", current.GetBool("gate_audit_complete") && complete)
		current.Set("gate_audit_drops", uint64(current.GetInt64("gate_audit_drops"))+drops)
		return tx.Save(current)
	})
	return errors.Join(flushErr, saveErr, projectionErr)
}

func (g *Runtime) ensureDefaultActiveSession() error {
	if g.config.Demo {
		return g.ensureDemoSession()
	}
	record, err := g.app.FindFirstRecordByFilter("sessions", "active=true")
	if errors.Is(err, sql.ErrNoRows) {
		collection, findErr := g.app.FindCollectionByNameOrId("sessions")
		if findErr != nil {
			return findErr
		}
		record = core.NewRecord(collection)
		record.Set("name", "Gateway Session")
		record.Set("active", true)
		err = g.app.Save(record)
	}
	if err != nil {
		return err
	}
	id := record.Id
	g.activeSessionID.Store(&id)
	return nil
}

func (g *Runtime) drainSessionGate(ctx context.Context, id string) (bool, uint64, error) {
	var gateErr, flushErr error
	if g.gate != nil {
		var status labgate.Status
		status, gateErr = g.gate.Status(ctx)
		if gateErr == nil && status.Armed && status.SessionID == id {
			_, gateErr = g.gate.Disarm(ctx)
		}
	}
	var drops uint64
	if g.audit != nil {
		flushErr = g.audit.Flush(ctx)
		drops = g.audit.DroppedForSession(id)
	}
	err := errors.Join(gateErr, flushErr)
	return err == nil && drops == 0, drops, err
}

// Probe admissions deliberately outlive their source session's deletion.
func deleteSessionData(app core.App, id string) error {
	for _, name := range []string{"traffic_chunks", "capture_intervals", "activity_blocks", "route_evidence", "flow_diagnostics", "dns_queries", "gate_events"} {
		if _, err := app.FindCollectionByNameOrId(name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return err
		}
		if _, err := app.DB().NewQuery("DELETE FROM " + name + " WHERE session={:id}").Bind(dbx.Params{"id": id}).Execute(); err != nil {
			return err
		}
	}
	return pruneDestinations(app)
}

func (g *Runtime) registerSessionControls(r *router.Router[*core.RequestEvent]) {
	r.POST("/api/infrareveal/sessions", func(e *core.RequestEvent) error {
		var request struct {
			Name             string `json:"name"`
			Ephemeral        bool   `json:"ephemeral"`
			RetentionMinutes int    `json:"retention_minutes"`
		}
		if err := e.BindBody(&request); err != nil {
			return e.BadRequestError("Invalid session", err)
		}
		if g.config.Demo {
			return e.BadRequestError("Disable DEMO_MODE before starting another session", nil)
		}
		var record *core.Record
		err := g.app.RunInTransaction(func(tx core.App) error {
			previous, err := tx.FindAllRecords("sessions", dbx.HashExp{"active": true})
			if err != nil {
				return err
			}
			for _, old := range previous {
				old.Set("active", false)
				if err := tx.Save(old); err != nil {
					return err
				}
			}
			collection, err := tx.FindCollectionByNameOrId("sessions")
			if err != nil {
				return err
			}
			record = core.NewRecord(collection)
			record.Set("name", request.Name)
			record.Set("active", true)
			record.Set("ephemeral", request.Ephemeral)
			record.Set("retention_minutes", request.RetentionMinutes)
			return tx.Save(record)
		})
		if err != nil {
			return e.BadRequestError("Cannot start session", err)
		}
		return g.sessionResponse(e, record.Id, http.StatusCreated)
	})
	r.POST("/api/infrareveal/sessions/{id}/end", func(e *core.RequestEvent) error {
		record, err := g.app.FindRecordById("sessions", e.Request.PathValue("id"))
		if err != nil {
			return timelineError(e, err)
		}
		if record.GetBool("demo") && g.config.Demo {
			return e.BadRequestError("Disable DEMO_MODE before ending its session", nil)
		}
		record.Set("active", false)
		if err := g.app.Save(record); err != nil {
			return e.BadRequestError("Cannot end session", err)
		}
		return g.sessionResponse(e, record.Id, http.StatusOK)
	})
	r.PATCH("/api/infrareveal/sessions/{id}", func(e *core.RequestEvent) error {
		var request struct {
			Name string `json:"name"`
		}
		if err := e.BindBody(&request); err != nil {
			return e.BadRequestError("Invalid name", err)
		}
		record, err := g.app.FindRecordById("sessions", e.Request.PathValue("id"))
		if err != nil {
			return timelineError(e, err)
		}
		record.Set("name", request.Name)
		if err := g.app.Save(record); err != nil {
			return e.BadRequestError("Cannot rename session", err)
		}
		return g.sessionResponse(e, record.Id, http.StatusOK)
	})
	r.DELETE("/api/infrareveal/sessions/{id}", func(e *core.RequestEvent) error {
		id := e.Request.PathValue("id")
		record, err := g.app.FindRecordById("sessions", id)
		if err != nil {
			return timelineError(e, err)
		}
		if record.GetBool("demo") && g.config.Demo {
			return e.BadRequestError("Disable DEMO_MODE before deleting its session", nil)
		}
		if _, _, err := g.drainSessionGate(e.Request.Context(), id); err != nil {
			return e.InternalServerError("Cannot drain session", err)
		}
		if err := g.app.Delete(record); err != nil {
			return e.InternalServerError("Cannot delete session", err)
		}
		return e.NoContent(http.StatusNoContent)
	})
}

func (g *Runtime) sessionResponse(e *core.RequestEvent, id string, status int) error {
	// Completion hooks may have committed audit status after the lifecycle save.
	record, err := g.app.FindRecordById("sessions", id)
	if err != nil {
		return timelineError(e, err)
	}
	session, err := data.Decode[data.Session](record)
	if err != nil {
		return err
	}
	return e.JSON(status, session)
}
