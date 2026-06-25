package migrations

import (
	"database/sql"
	"errors"

	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
	"github.com/pocketbase/pocketbase/tools/types"
)

func init() {
	m.Register(func(txApp core.App) error {
		sessions, err := ensureCollection(txApp, "sessions", []core.Field{
			&core.TextField{Name: "name", Max: 200},
			&core.BoolField{Name: "active"},
		})
		if err != nil {
			return err
		}

		if _, err := ensureCollection(txApp, "clients", []core.Field{
			&core.TextField{Name: "mac", Max: 64},
			&core.TextField{Name: "ip", Max: 64, Required: true},
			&core.TextField{Name: "hostname", Max: 255},
			&core.DateField{Name: "first_seen"},
			&core.DateField{Name: "last_seen"},
		}); err != nil {
			return err
		}

		flows, err := ensureCollection(txApp, "flows", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1},
			&core.TextField{Name: "flow_key", Max: 500, Required: true},
			&core.TextField{Name: "client_ip", Max: 64, Required: true},
			&core.TextField{Name: "destination_ip", Max: 64, Required: true},
			&core.NumberField{Name: "source_port", OnlyInt: true},
			&core.NumberField{Name: "destination_port", OnlyInt: true},
			&core.TextField{Name: "protocol", Max: 16, Required: true},
			&core.TextField{Name: "state", Max: 64},
			&core.DateField{Name: "start"},
			&core.DateField{Name: "last_seen"},
			&core.NumberField{Name: "bytes_out", OnlyInt: true},
			&core.NumberField{Name: "bytes_in", OnlyInt: true},
			&core.NumberField{Name: "packets_out", OnlyInt: true},
			&core.NumberField{Name: "packets_in", OnlyInt: true},
			&core.TextField{Name: "source", Max: 64},
		})
		if err != nil {
			return err
		}
		flows.AddIndex("idx_flows_session_key", true, "session, flow_key", "")
		flows.AddIndex("idx_flows_client_last_seen", false, "client_ip, last_seen", "")
		if err := txApp.Save(flows); err != nil {
			return err
		}

		dnsQueries, err := ensureCollection(txApp, "dns_queries", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1},
			&core.TextField{Name: "client_ip", Max: 64},
			&core.TextField{Name: "query_name", Max: 500, Required: true},
			&core.TextField{Name: "query_type", Max: 32},
			&core.JSONField{Name: "answers"},
			&core.DateField{Name: "timestamp"},
			&core.TextField{Name: "source", Max: 64},
		})
		if err != nil {
			return err
		}
		dnsQueries.AddIndex("idx_dns_session_name_time", false, "session, query_name, timestamp", "")
		dnsQueries.AddIndex("idx_dns_client_time", false, "client_ip, timestamp", "")
		return txApp.Save(dnsQueries)
	}, func(txApp core.App) error {
		for _, name := range []string{"dns_queries", "flows", "clients"} {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err == nil {
				if err := txApp.Delete(collection); err != nil {
					return err
				}
			}
		}

		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err != nil {
			return nil
		}
		sessions.Fields.RemoveByName("name")
		sessions.Fields.RemoveByName("active")
		return txApp.Save(sessions)
	})
}

func ensureCollection(txApp core.App, name string, fields []core.Field) (*core.Collection, error) {
	collection, err := txApp.FindCollectionByNameOrId(name)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return nil, err
		}
		collection = core.NewBaseCollection(name)
		openRule := ""
		collection.ListRule = types.Pointer(openRule)
		collection.ViewRule = types.Pointer(openRule)
	}

	for _, field := range fields {
		if collection.Fields.GetByName(field.GetName()) == nil {
			collection.Fields.Add(field)
		}
	}

	if err := txApp.Save(collection); err != nil {
		return nil, err
	}
	return collection, nil
}
