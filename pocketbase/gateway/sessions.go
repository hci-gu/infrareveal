package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/pocketbase/pocketbase/core"
	"myapp/labgate"
	"time"
)

func (g *Runtime) registerSessionHooks() {
	// HTTP serialization is installed on the root router, covering PocketBase's
	// batch transaction once. Never acquire that lock from nested record hooks.
	g.app.OnRecordDeleteRequest("sessions").BindFunc(func(e *core.RecordRequestEvent) error {
		// Direct deletes can flush before removing the audit parent. Batch CRUD is
		// already inside a transaction: its post-commit delete hook drains instead.
		if e.Get(core.RequestEventKeyInfoContext) != core.RequestInfoContextBatch {
			if _, _, err := g.drainSessionGate(e.Request.Context(), e.Record.Id); err != nil {
				return err
			}
		}
		return e.Next()
	})
	g.app.OnRecordCreate("sessions").BindFunc(func(e *core.RecordEvent) error {
		if err := g.prepareSession(e.Record); err != nil {
			return err
		}
		if e.Record.GetDateTime("started_at").IsZero() {
			e.Record.Set("started_at", time.Now().UTC())
		}
		e.Record.Set("gate_audit_complete", true)
		e.Record.Set("gate_audit_drops", 0)
		return e.Next()
	})
	g.app.OnRecordUpdate("sessions").BindFunc(func(e *core.RecordEvent) error {
		if err := g.prepareSession(e.Record); err != nil {
			return err
		}
		if e.Record.GetBool("active") {
			e.Record.Set("gate_audit_complete", true)
			e.Record.Set("gate_audit_drops", 0)
		} else if e.Record.GetDateTime("ended_at").IsZero() {
			e.Record.Set("ended_at", time.Now().UTC())
		}
		return e.Next()
	})
	// PocketBase defers success hooks until the enclosing transaction commits.
	// Failed saves/rollbacks therefore never publish a speculative session ID.
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
	g.app.OnRecordAfterDeleteSuccess("sessions").BindFunc(func(e *core.RecordEvent) error {
		if g.CurrentSessionID() == e.Record.Id {
			g.activeSessionID.Store(nil)
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, _, err := g.drainSessionGate(ctx, e.Record.Id); err != nil {
			return err
		}
		return e.Next()
	})
}

func (g *Runtime) prepareSession(record *core.Record) error {
	normalizeEphemeralSession(record, time.Now().UTC())
	if g.config.Demo && record.GetBool("active") && !record.GetBool("demo") {
		return fmt.Errorf("disable DEMO_MODE before starting another session")
	}
	if record.GetBool("active") {
		record.Set("ended_at", "")
	}
	return nil
}

// Completion runs after commit, outside the transaction that ended the session.
// This lets the audit writer flush against the database without a lock cycle.
func (g *Runtime) finishSession(record *core.Record) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	complete, drops, flushErr := g.drainSessionGate(ctx, record.Id)
	if g.audit == nil && flushErr == nil {
		return nil
	}

	// Reload the committed model so this bookkeeping update cannot replay the
	// active -> inactive transition or overwrite a concurrent session edit.
	saveErr := g.app.RunInTransaction(func(tx core.App) error {
		current, err := tx.FindRecordById("sessions", record.Id)
		if err != nil {
			return err
		}
		if current.GetBool("active") {
			return nil
		}
		current.Set("gate_audit_complete", complete)
		current.Set("gate_audit_drops", drops)
		return tx.Save(current)
	})
	return errors.Join(flushErr, saveErr)
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
