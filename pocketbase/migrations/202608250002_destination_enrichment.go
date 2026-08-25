package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("destinations")
		if err != nil {
			return err
		}
		if collection.Fields.GetByName("enriched_at") == nil {
			collection.Fields.Add(&core.DateField{Name: "enriched_at"})
		}
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("destinations")
		if err != nil {
			return nil
		}
		collection.Fields.RemoveByName("enriched_at")
		return txApp.Save(collection)
	})
}
