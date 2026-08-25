package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("dns_queries")
		if err != nil {
			return err
		}
		if collection.Fields.GetByName("aliases") == nil {
			collection.Fields.Add(&core.JSONField{Name: "aliases"})
		}
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("dns_queries")
		if err != nil {
			return nil
		}
		collection.Fields.RemoveByName("aliases")
		return txApp.Save(collection)
	})
}
