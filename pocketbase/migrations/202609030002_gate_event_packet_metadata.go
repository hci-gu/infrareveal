package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

// Keep upgrades safe for installations that already ran the initial gate
// migration while fresh databases receive the same fields idempotently.
func init() {
	m.Register(func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("gate_events")
		if err != nil {
			return err
		}
		fields := []core.Field{
			&core.SelectField{Name: "mode", MaxSelect: 1, Values: []string{"flow", "strict", "dns"}},
			&core.SelectField{Name: "direction", MaxSelect: 1, Values: []string{"client_to_remote", "remote_to_client"}},
			&core.NumberField{Name: "wire_bytes", OnlyInt: true},
			&core.NumberField{Name: "payload_bytes", OnlyInt: true},
			&core.NumberField{Name: "tcp_flags", OnlyInt: true},
		}
		for _, field := range fields {
			if collection.Fields.GetByName(field.GetName()) == nil {
				collection.Fields.Add(field)
			}
		}
		return txApp.Save(collection)
	}, func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("gate_events")
		if err != nil {
			return nil
		}
		for _, name := range []string{"mode", "direction", "wire_bytes", "payload_bytes", "tcp_flags"} {
			collection.Fields.RemoveByName(name)
		}
		return txApp.Save(collection)
	})
}
