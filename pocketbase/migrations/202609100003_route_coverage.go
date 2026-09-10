package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		collection, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		collection.Fields.Add(&core.JSONField{Name: "probe_details", MaxSize: 32768}, &core.JSONField{Name: "alternate_routes", MaxSize: 196608})
		return app.Save(collection)
	}, func(app core.App) error {
		collection, err := app.FindCollectionByNameOrId("routes")
		if err != nil {
			return err
		}
		collection.Fields.RemoveByName("probe_details")
		collection.Fields.RemoveByName("alternate_routes")
		return app.Save(collection)
	})
}
