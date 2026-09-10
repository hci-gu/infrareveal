package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		observations, err := ensureCollection(app, "route_observations", []core.Field{
			&core.TextField{Name: "cache_key", Required: true}, &core.TextField{Name: "attempt_id", Required: true},
			&core.NumberField{Name: "revision", OnlyInt: true}, &core.JSONField{Name: "snapshot", MaxSize: 131072},
			&core.DateField{Name: "measured_at"},
		})
		if err != nil {
			return err
		}
		observations.AddIndex("idx_route_observation_revision", true, "attempt_id, revision", "")
		if err := app.Save(observations); err != nil {
			return err
		}
		cache, err := ensureCollection(app, "route_cache", []core.Field{
			&core.TextField{Name: "cache_key", Required: true}, &core.JSONField{Name: "entry", MaxSize: 262144},
			&core.DateField{Name: "last_used_at"},
		})
		if err != nil {
			return err
		}
		cache.AddIndex("idx_route_cache_key", true, "cache_key", "")
		if err := app.Save(cache); err != nil {
			return err
		}
		routes, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		routes.Fields.Add(
			&core.TextField{Name: "binding_key"}, &core.TextField{Name: "network_context"},
			&core.TextField{Name: "attempt_id"}, &core.NumberField{Name: "revision", OnlyInt: true},
			&core.TextField{Name: "observation_id"}, &core.TextField{Name: "status"}, &core.TextField{Name: "provenance"},
			&core.DateField{Name: "available_at"}, &core.DateField{Name: "measured_at"},
			&core.DateField{Name: "fresh_until"}, &core.DateField{Name: "valid_until"},
			&core.BoolField{Name: "destination_reached"}, &core.NumberField{Name: "responding_hops", OnlyInt: true},
			&core.NumberField{Name: "located_hops", OnlyInt: true}, &core.JSONField{Name: "destination_location"},
		)
		routes.AddIndex("idx_route_binding_available", false, "session, binding_key, available_at", "")
		return app.Save(routes)
	}, func(app core.App) error {
		routes, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		for _, name := range []string{"binding_key", "network_context", "attempt_id", "revision", "observation_id", "status", "provenance", "available_at", "measured_at", "fresh_until", "valid_until", "destination_reached", "responding_hops", "located_hops", "destination_location"} {
			routes.Fields.RemoveByName(name)
		}
		routes.RemoveIndex("idx_route_binding_available")
		if err := app.Save(routes); err != nil {
			return err
		}
		for _, name := range []string{"route_cache", "route_observations"} {
			c, err := app.FindCollectionByNameOrId(name)
			if err != nil {
				return err
			}
			if err = app.Delete(c); err != nil {
				return err
			}
		}
		return nil
	})
}
