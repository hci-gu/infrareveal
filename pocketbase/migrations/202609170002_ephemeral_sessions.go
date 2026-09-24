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
		sessions.Fields.Add(&core.BoolField{Name: "ephemeral"})
		return app.Save(sessions)
	}, func(app core.App) error {
		sessions, err := app.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		sessions.Fields.RemoveByName("ephemeral")
		return app.Save(sessions)
	})
}
