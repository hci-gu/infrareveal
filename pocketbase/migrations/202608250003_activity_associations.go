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
		flows, err := txApp.FindCollectionByNameOrId("flows")
		if err != nil {
			return err
		}

		episodes, err := ensureCollection(txApp, "activity_episodes", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "episode_key", Max: 500, Required: true},
			&core.TextField{Name: "client_ip", Max: 64, Required: true},
			&core.TextField{Name: "site_key", Max: 255, Required: true},
			&core.TextField{Name: "label", Max: 255, Required: true},
			&core.TextField{Name: "anchor_hostname", Max: 500, Required: true},
			&core.DateField{Name: "start"},
			&core.DateField{Name: "last_seen"},
			&core.TextField{Name: "confidence", Max: 32, Required: true},
			&core.TextField{Name: "explanation", Max: 1000},
		})
		if err != nil {
			return err
		}
		episodes.AddIndex("idx_activity_episodes_session_client_start", false, "session, client_ip, start", "")
		episodes.AddIndex("idx_activity_episodes_key", true, "episode_key", "")
		if err := txApp.Save(episodes); err != nil {
			return err
		}

		associations, err := ensureCollection(txApp, "flow_associations", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.RelationField{Name: "flow", CollectionId: flows.Id, MaxSelect: 1, Required: true},
			&core.RelationField{Name: "episode", CollectionId: episodes.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "parent_site_key", Max: 255, Required: true},
			&core.TextField{Name: "parent_label", Max: 255, Required: true},
			&core.TextField{Name: "relationship", Max: 64, Required: true},
			&core.TextField{Name: "confidence", Max: 32, Required: true},
			&core.NumberField{Name: "score", OnlyInt: true},
			&core.TextField{Name: "explanation", Max: 1000},
			&core.DateField{Name: "observed_at"},
		})
		if err != nil {
			return err
		}
		associations.AddIndex("idx_flow_associations_flow", true, "flow", "")
		associations.AddIndex("idx_flow_associations_session_parent", false, "session, parent_site_key", "")
		return txApp.Save(associations)
	}, func(txApp core.App) error {
		for _, name := range []string{"flow_associations", "activity_episodes"} {
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
