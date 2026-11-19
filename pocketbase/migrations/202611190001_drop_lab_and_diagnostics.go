package migrations

import (
	"database/sql"
	"errors"

	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

// Proxy Lab (traffic gate, passive trace) and raw diagnostics were removed.
// Drop their optional collections and the session/probe fields they owned.
func init() {
	m.Register(func(app core.App) error {
		for _, name := range []string{"gate_events", "flow_diagnostics", "dns_queries"} {
			c, err := app.FindCollectionByNameOrId(name)
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			if err != nil {
				return err
			}
			if err := app.Delete(c); err != nil {
				return err
			}
		}
		for collection, fields := range map[string][]string{
			"sessions":   {"gate_audit_complete", "gate_audit_drops", "diagnostics"},
			"probe_runs": {"details"},
		} {
			c, err := app.FindCollectionByNameOrId(collection)
			if err != nil {
				return err
			}
			changed := false
			for _, field := range fields {
				if c.Fields.GetByName(field) != nil {
					c.Fields.RemoveByName(field)
					changed = true
				}
			}
			if changed {
				if err := app.Save(c); err != nil {
					return err
				}
			}
		}
		return nil
	}, nil)
}
