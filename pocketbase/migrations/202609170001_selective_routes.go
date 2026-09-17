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
		for _, name := range []string{"route_outcomes", "route_budget_state", "route_evidence_updates"} {
			c, err := ensureCollection(app, name, []core.Field{
				&core.TextField{Name: "key", Required: true}, &core.RelationField{Name: "session", CollectionId: sessions.Id, CascadeDelete: true, MaxSelect: 1},
				&core.TextField{Name: "network_context"}, &core.TextField{Name: "binding_key"},
				&core.TextField{Name: "kind"}, &core.DateField{Name: "available_at"},
				&core.JSONField{Name: "value", MaxSize: 65536},
			})
			if err != nil {
				return err
			}
			c.AddIndex("idx_"+name+"_key", true, "key", "")
			c.AddIndex("idx_"+name+"_session", false, "session, available_at", "")
			// Operational spending is writable only through the coordinator.
			if name == "route_budget_state" {
				c.ListRule = nil
				c.ViewRule = nil
			}
			c.CreateRule = nil
			c.UpdateRule = nil
			c.DeleteRule = nil
			if err = app.Save(c); err != nil {
				return err
			}
		}
		c, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		c.Fields.Add(&core.NumberField{Name: "schema_version", OnlyInt: true}, &core.TextField{Name: "fingerprint"}, &core.TextField{Name: "evidence_class"}, &core.TextField{Name: "evidence_reason"})
		c.AddIndex("idx_route_material", true, "session, network_context, binding_key, fingerprint", "schema_version = 2")
		return app.Save(c)
	}, func(app core.App) error {
		// Preserve recordings on rollback; old binaries ignore additive fields.
		return nil
	})
}
