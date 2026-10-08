package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
)

type clearObservationsResult struct {
	Deleted map[string]int `json:"deleted"`
	Skipped []string       `json:"skipped"`
}

// Clear disarms fail-open, drains audit, and joins all observation producers
// before deleting. Restart uses fresh DNS/packet state and suppressed conntrack
// tuples, so accepted pre-clear work cannot recreate cleared records.
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
	if g.observation != nil {
		if err := g.observation.Quiesce(ctx); err != nil {
			// No deletion has begun. Recover intake after outstanding writes finish;
			// serialize the restart against any later clear or shutdown.
			go func() {
				_ = g.observation.Wait(context.Background())
				g.operations.Lock()
				defer g.operations.Unlock()
				if !g.closed {
					g.observation.Start()
				}
			}()
			return result, err
		}
		defer g.observation.Start()
		if err := g.observation.SuppressCurrentFlows(); err != nil {
			return result, fmt.Errorf("snapshot active conntrack flows before clearing: %w", err)
		}
	}
	if g.routes != nil {
		if err := g.routes.ResetContext(ctx); err != nil {
			return result, err
		}
	}
	// Dependency order preserves per-record hooks and realtime delete events.
	for _, name := range []string{"gate_events", "flow_activity_chunks", "flow_activity_windows", "flow_activity_status", "flow_associations", "activity_episodes", "flow_attributions", "routes", "route_cache", "route_observations", "route_outcomes", "route_evidence_updates", "traceroutes", "packets", "flows", "dns_queries", "destinations", "clients"} {
		if _, err := g.app.FindCollectionByNameOrId(name); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				result.Skipped = append(result.Skipped, name)
				continue
			}
			return result, err
		}
		for {
			if err := ctx.Err(); err != nil {
				return result, err
			}
			records, err := g.app.FindRecordsByFilter(name, "", "id", 200, 0)
			if err != nil {
				return result, err
			}
			if len(records) == 0 {
				break
			}
			for _, record := range records {
				if err := g.app.Delete(record); err != nil {
					return result, fmt.Errorf("clear %s/%s: %w", name, record.Id, err)
				}
				result.Deleted[name]++
			}
		}
	}
	return result, nil
}
