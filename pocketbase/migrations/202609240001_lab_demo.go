package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		sessions, err := app.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		minMinutes, maxMinutes := float64(0), float64(1440)
		sessions.Fields.Add(&core.BoolField{Name: "demo"}, &core.NumberField{Name: "retention_minutes", OnlyInt: true, Min: &minMinutes, Max: &maxMinutes})
		sessions.AddIndex("idx_sessions_single_demo", true, "demo", "demo = true")
		if err = app.Save(sessions); err != nil {
			return err
		}
		// Preserve existing five-minute ephemeral sessions; new demo sessions use 30.
		if _, err = app.DB().NewQuery("UPDATE sessions SET retention_minutes=5 WHERE ephemeral=true").Execute(); err != nil {
			return err
		}

		if _, err = app.DB().NewQuery(`CREATE TABLE _domain_catalogue_checkpoints (
          source TEXT NOT NULL, source_id TEXT NOT NULL, revision TEXT NOT NULL,
          state TEXT NOT NULL, PRIMARY KEY (source, source_id))`).Execute(); err != nil {
			return err
		}

		c := core.NewBaseCollection("domain_catalogue")
		// Superuser-only review and export. No client/session identifiers are retained.
		c.Fields.Add(&core.TextField{Name: "domain", Required: true}, &core.DateField{Name: "first_seen"}, &core.DateField{Name: "last_seen"},
			&core.NumberField{Name: "dns_count", OnlyInt: true}, &core.NumberField{Name: "high_flow_count", OnlyInt: true},
			&core.NumberField{Name: "medium_flow_count", OnlyInt: true}, &core.NumberField{Name: "low_flow_count", OnlyInt: true},
			&core.JSONField{Name: "hostnames"}, &core.JSONField{Name: "cname_examples"},
			&core.SelectField{Name: "review_status", Values: []string{"pending", "approved", "rejected"}, MaxSelect: 1},
			&core.TextField{Name: "proposed_group"}, &core.TextField{Name: "notes"})
		ensureRevisionFields(c)
		c.AddIndex("idx_catalogue_domain", true, "domain", "")
		return app.Save(c)
	}, func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("domain_catalogue")
		if err != nil {
			return err
		}
		if err = app.Delete(c); err != nil {
			return err
		}

		sessions, err := app.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		sessions.Fields.RemoveByName("demo")
		sessions.Fields.RemoveByName("retention_minutes")
		sessions.RemoveIndex("idx_sessions_single_demo")
		if err = app.Save(sessions); err != nil {
			return err
		}
		if _, err = app.DB().NewQuery("DROP TABLE _domain_catalogue_checkpoints").Execute(); err != nil {
			return err
		}

		return nil
	})
}
