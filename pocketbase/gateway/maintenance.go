package gateway

import (
	"context"
	"database/sql"
	"errors"
	"log"
	"strings"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/labgate"
	"myapp/observer"
	"myapp/routing"
	"myapp/timeline"
)

func sessionRetention(record *core.Record) time.Duration { return timeline.RetentionWindow(record) }

// Retention moves a separate durable edge; it never changes recording identity
// or reopens an ended session.
func normalizeEphemeralSession(record *core.Record, now time.Time) {
	floor := record.GetInt64("started_ms")
	if record.GetBool("ephemeral") && record.GetBool("active") {
		floor = max(floor, now.Add(-sessionRetention(record)).UnixMilli())
		var policy data.Policy
		_ = record.UnmarshalJSONField("policy", &policy)
		bucket := policy.BucketMS
		if bucket <= 0 {
			bucket = 50
		}
		floor = (floor + bucket - 1) / bucket * bucket
	}
	record.Set("retained_from_ms", max(floor, record.GetInt64("retained_from_ms")))
}

func (g *Runtime) maintain(ctx context.Context) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now().UTC()
		if err := lockOperation(ctx, &g.operations); err != nil {
			return
		}
		err := g.sweep(now)
		g.operations.Unlock()
		g.updateDemoMaintenance(now, err)
		if err != nil {
			log.Printf("gateway maintenance: %v", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

func (g *Runtime) pruneEphemeralSessions(now time.Time) error {
	sessions, err := g.app.FindRecordsByFilter("sessions", "ephemeral=true && active=true", "", 0, 0)
	if err != nil {
		return err
	}
	var errs []error
	for _, session := range sessions {
		err := g.app.RunInTransaction(func(tx core.App) error {
			current, err := tx.FindRecordById("sessions", session.Id)
			if err != nil {
				return err
			}
			if !current.GetBool("ephemeral") || !current.GetBool("active") {
				return nil
			}
			cutoff := max(current.GetInt64("started_ms"), current.GetInt64("retained_from_ms"), now.Add(-sessionRetention(current)).UnixMilli())
			var policy data.Policy
			if err := current.UnmarshalJSONField("policy", &policy); err != nil {
				return err
			}
			bucket := policy.BucketMS
			if bucket <= 0 {
				bucket = 50
			}
			cutoff = (cutoff + bucket - 1) / bucket * bucket
			if err := observer.PruneSession(tx, session.Id, cutoff); err != nil {
				return err
			}
			if err := routing.RetainSession(tx, session.Id, time.UnixMilli(cutoff)); err != nil {
				return err
			}
			if _, err := tx.FindCollectionByNameOrId("gate_events"); err == nil {
				if err := labgate.RetainSession(tx, session.Id, time.UnixMilli(cutoff)); err != nil {
					return err
				}
			} else if !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			_, err = tx.DB().NewQuery("UPDATE sessions SET retained_from_ms={:cut}, revision=revision+1 WHERE id={:id} AND retained_from_ms < {:cut}").Bind(dbx.Params{"id": session.Id, "cut": cutoff}).Execute()
			return err
		})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// Chores share a clock, not a failure domain. Saved product history is retained;
// optional diagnostics and durable probe charges have their own bounds.
func (g *Runtime) sweep(now time.Time) error {
	return errors.Join(g.pruneEphemeralSessions(now), routing.RetainShared(g.app, now), pruneDestinations(g.app), g.pruneDiagnostics(now))
}

func pruneDestinations(app core.App) error {
	_, err := app.DB().NewQuery("DELETE FROM destinations WHERE NOT EXISTS (SELECT 1 FROM traffic_chunks WHERE destination_id=destinations.id)").Execute()
	return err
}

// Bound diagnostic payload bytes independently of traffic retention. Queued gate
// records belong to the bounded fail-open controller and must not be evicted
// before their terminal verdict has been recorded.
func (g *Runtime) pruneDiagnostics(now time.Time) error {
	retention := g.config.DiagnosticRetention
	if retention <= 0 {
		retention = time.Hour
	}
	budget := g.config.DiagnosticMaxBytes
	if budget <= 0 {
		budget = 16 * 1024 * 1024
	}
	var errs []error
	for _, spec := range []struct{ name, age, predicate string }{
		{"flow_diagnostics", "last_ms", "1=1"},
		{"dns_queries", "observed_ms", "1=1"},
		{"gate_events", "queued_at", "state != 'queued'"},
	} {
		collection, err := g.app.FindCollectionByNameOrId(spec.name)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			errs = append(errs, err)
			continue
		}
		err = g.app.RunInTransaction(func(tx core.App) error {
			var cutoff any = now.Add(-retention).UnixMilli()
			if spec.age == "queued_at" {
				cutoff = now.Add(-retention).UTC().Format("2006-01-02 15:04:05.000Z")
			}
			if _, err := tx.DB().NewQuery("DELETE FROM " + spec.name + " WHERE " + spec.predicate + " AND " + spec.age + " < {:cut}").Bind(dbx.Params{"cut": cutoff}).Execute(); err != nil {
				return err
			}
			// json_object includes field names and escapes JSON/text, conservatively
			// accounting for each stored row without loading every payload into Go.
			fields := make([]string, 0, len(collection.Fields))
			for _, field := range collection.Fields {
				name := field.GetName()
				fields = append(fields, "'"+strings.ReplaceAll(name, "'", "''")+"', \""+strings.ReplaceAll(name, "\"", "\"\"")+"\"")
			}
			size := "length(CAST(json_object(" + strings.Join(fields, ",") + ") AS BLOB))"
			query := "DELETE FROM " + spec.name + " WHERE id IN (SELECT id FROM (SELECT id, SUM(" + size + ") OVER (ORDER BY updated DESC,id DESC ROWS UNBOUNDED PRECEDING) AS payload_bytes FROM " + spec.name + " WHERE " + spec.predicate + ") WHERE payload_bytes > {:budget})"
			_, err := tx.DB().NewQuery(query).Bind(dbx.Params{"budget": budget / 3}).Execute()
			return err
		})
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}
