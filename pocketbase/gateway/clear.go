package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
)

type clearObservationsResult struct {
	Deleted map[string]int `json:"deleted"`
	Skipped []string       `json:"skipped"`
}

// Clear disarms fail-open, drains audit, and joins all observation producers
// before deleting. Restart opens a fresh capture epoch, so accepted pre-clear
// work cannot recreate cleared records. Probe admissions remain charged.
func (g *Runtime) Clear(ctx context.Context) (clearObservationsResult, error) {
	if err := lockOperation(ctx, &g.operations); err != nil {
		return clearObservationsResult{}, err
	}
	defer g.operations.Unlock()
	result := clearObservationsResult{Deleted: map[string]int{}, Skipped: []string{}}
	if g.closed {
		return result, fmt.Errorf("gateway is closed")
	}
	if g.gate != nil {
		if _, err := g.gate.Disarm(ctx); err != nil {
			return result, err
		}
	}
	if g.audit != nil {
		if err := g.audit.Flush(ctx); err != nil {
			return result, err
		}
	}
	resume, err := g.pauseObservation(ctx)
	if err != nil {
		return result, err
	}
	defer resume()
	if g.routes != nil {
		if err := g.routes.ResetContext(ctx); err != nil {
			return result, err
		}
	}
	// Core data and optional diagnostics have no dependency on the durable quota
	// ledger. Never delete probe_runs here, even if their sessions were removed.
	err = g.app.RunInTransaction(func(tx core.App) error {
		for _, name := range []string{"gate_events", "flow_diagnostics", "dns_queries", "activity_blocks", "traffic_chunks", "capture_intervals", "route_evidence", "destinations"} {
			if _, err := tx.FindCollectionByNameOrId(name); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					result.Skipped = append(result.Skipped, name)
					continue
				}
				return err
			}
			if err := ctx.Err(); err != nil {
				return err
			}
			deleted, err := tx.DB().NewQuery("DELETE FROM " + name).Execute()
			if err != nil {
				return fmt.Errorf("clear %s: %w", name, err)
			}
			count, err := deleted.RowsAffected()
			if err != nil {
				return err
			}
			result.Deleted[name] = int(count)
		}
		// Clear removes the old contents of the crossing bin, so rounding down
		// admits fresh packets immediately. Rolling expiry instead rounds up.
		_, err := tx.DB().NewQuery("UPDATE sessions SET revision=revision+1, retained_from_ms=MAX(retained_from_ms, CASE WHEN active THEN {:now}-{:now}%COALESCE(NULLIF(json_extract(policy,'$.bucket_ms'),0),50) ELSE ended_ms END), block_watermark_ms=0, capture=json_object('epoch',{:epoch})").Bind(dbx.Params{"now": time.Now().UnixMilli(), "epoch": data.NewID()}).Execute()
		return err
	})
	return result, err
}
