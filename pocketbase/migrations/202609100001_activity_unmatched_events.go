package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		status, err := app.FindCollectionByNameOrId("flow_activity_status")
		if err != nil {
			return err
		}
		if status.Fields.GetByName("unmatched_events") == nil {
			status.Fields.Add(&core.NumberField{Name: "unmatched_events", OnlyInt: true})
		}
		// Existing recordings retain their original quality reports. Their old
		// combined loss counter cannot be split reliably after the fact.
		return app.Save(status)
	}, func(app core.App) error {
		status, err := app.FindCollectionByNameOrId("flow_activity_status")
		if err != nil {
			return err
		}
		status.Fields.RemoveByName("unmatched_events")
		return app.Save(status)
	})
}
