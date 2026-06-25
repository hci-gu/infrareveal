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
		dnsQueries, err := txApp.FindCollectionByNameOrId("dns_queries")
		if err != nil {
			return err
		}

		attributions, err := ensureCollection(txApp, "flow_attributions", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1},
			&core.RelationField{Name: "flow", CollectionId: flows.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "candidate_hostname", Max: 500},
			&core.TextField{Name: "source_signal", Max: 64, Required: true},
			&core.TextField{Name: "confidence", Max: 32, Required: true},
			&core.TextField{Name: "explanation", Max: 1000},
			&core.RelationField{Name: "dns_query", CollectionId: dnsQueries.Id, MaxSelect: 1},
			&core.DateField{Name: "observed_at"},
		})
		if err != nil {
			return err
		}

		attributions.AddIndex("idx_flow_attributions_flow", true, "flow", "")
		attributions.AddIndex("idx_flow_attributions_session_confidence", false, "session, confidence", "")
		return txApp.Save(attributions)
	}, func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("flow_attributions")
		if err == nil {
			return txApp.Delete(collection)
		}
		return nil
	})
}
