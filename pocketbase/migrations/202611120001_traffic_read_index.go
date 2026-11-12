package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("traffic_chunks")
		if err != nil {
			return err
		}
		c.AddIndex("traffic_binding_time", false, "session,client_id,service_key,destination_id,start_ms,id", "")
		return app.Save(c)
	}, nil)
}
