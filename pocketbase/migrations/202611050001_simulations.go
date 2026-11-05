package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
	"myapp/data"
)

func init() {
	m.Register(func(app core.App) error {
		sessions, err := app.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		data.SimulationFields(sessions)
		return app.Save(sessions)
	}, nil)
}
