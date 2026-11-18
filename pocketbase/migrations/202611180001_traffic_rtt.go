package migrations

import (
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

// Passive gateway↔server round-trip time per traffic chunk (see observer/rtt.go).
func init() {
	m.Register(func(app core.App) error {
		c, err := app.FindCollectionByNameOrId("traffic_chunks")
		if err != nil {
			return err
		}
		minimum, maximum := float64(0), float64(9007199254740991)
		c.Fields.Add(&core.NumberField{Name: "rtt_us", OnlyInt: true, Min: &minimum, Max: &maximum}, &core.TextField{Name: "rtt_source", Max: 8})
		return app.Save(c)
	}, nil)
}
