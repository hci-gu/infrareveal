package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}

		destinations, err := ensureCollection(txApp, "destinations", []core.Field{
			&core.TextField{Name: "ip", Max: 64, Required: true},
			&core.TextField{Name: "reverse_dns", Max: 500},
			&core.NumberField{Name: "asn", OnlyInt: true},
			&core.TextField{Name: "organization", Max: 500},
			&core.TextField{Name: "provider_label", Max: 500},
			&core.TextField{Name: "city", Max: 200},
			&core.TextField{Name: "country", Max: 200},
			&core.NumberField{Name: "lat"},
			&core.NumberField{Name: "lon"},
			&core.DateField{Name: "first_seen"},
			&core.DateField{Name: "last_seen"},
			&core.TextField{Name: "source", Max: 64},
		})
		if err != nil {
			return err
		}
		destinations.AddIndex("idx_destinations_ip", true, "ip", "")
		if err := txApp.Save(destinations); err != nil {
			return err
		}

		routes, err := ensureCollection(txApp, "routes", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1},
			&core.RelationField{Name: "destination", CollectionId: destinations.Id, MaxSelect: 1},
			&core.TextField{Name: "destination_ip", Max: 64, Required: true},
			&core.NumberField{Name: "destination_port", OnlyInt: true},
			&core.TextField{Name: "protocol", Max: 16},
			&core.TextField{Name: "method", Max: 64, Required: true},
			&core.JSONField{Name: "hops"},
			&core.BoolField{Name: "complete"},
			&core.TextField{Name: "error", Max: 1000},
			&core.DateField{Name: "started_at"},
			&core.DateField{Name: "completed_at"},
		})
		if err != nil {
			return err
		}
		routes.AddIndex("idx_routes_session_destination_method", false, "session, destination_ip, method", "")
		return txApp.Save(routes)
	}, func(txApp core.App) error {
		for _, name := range []string{"routes", "destinations"} {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err == nil {
				if err := txApp.Delete(collection); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
