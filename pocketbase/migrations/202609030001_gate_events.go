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
		gateEvents, err := ensureCollection(txApp, "gate_events", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "decision_id", Max: 128, Required: true},
			&core.TextField{Name: "flow_key", Max: 500, Required: true},
			&core.TextField{Name: "client_ip", Max: 64, Required: true},
			&core.TextField{Name: "destination_ip", Max: 64, Required: true},
			&core.NumberField{Name: "source_port", OnlyInt: true},
			&core.NumberField{Name: "destination_port", OnlyInt: true},
			&core.TextField{Name: "protocol", Max: 16, Required: true},
			&core.SelectField{Name: "mode", MaxSelect: 1, Values: []string{"flow", "strict", "dns"}},
			&core.SelectField{Name: "direction", MaxSelect: 1, Values: []string{"client_to_remote", "remote_to_client"}},
			&core.NumberField{Name: "wire_bytes", OnlyInt: true},
			&core.NumberField{Name: "payload_bytes", OnlyInt: true},
			&core.NumberField{Name: "tcp_flags", OnlyInt: true},
			&core.NumberField{Name: "packet_count", OnlyInt: true},
			&core.SelectField{Name: "state", MaxSelect: 1, Required: true, Values: []string{"queued", "approved", "rejected", "expired", "bypassed", "drained"}},
			&core.TextField{Name: "actor", Max: 128},
			&core.TextField{Name: "reason", Max: 500},
			&core.SelectField{Name: "verdict_source", MaxSelect: 1, Values: []string{"operator", "watchdog", "overflow", "shutdown", "system"}},
			&core.DateField{Name: "queued_at", Required: true},
			&core.DateField{Name: "decided_at"},
			&core.NumberField{Name: "wait_ms", OnlyInt: true},
			&core.AutodateField{Name: "created", OnCreate: true},
			&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true},
		})
		if err != nil {
			return err
		}
		// Gate audit visibility follows flows, but browser clients can never
		// mutate the audit trail.
		gateEvents.ListRule = flows.ListRule
		gateEvents.ViewRule = flows.ViewRule
		gateEvents.CreateRule = nil
		gateEvents.UpdateRule = nil
		gateEvents.DeleteRule = nil
		gateEvents.AddIndex("idx_gate_events_session_queued", false, "session, queued_at", "")
		gateEvents.AddIndex("idx_gate_events_session_decision", true, "session, decision_id", "")
		gateEvents.AddIndex("idx_gate_events_session_flow", false, "session, flow_key", "")
		return txApp.Save(gateEvents)
	}, func(txApp core.App) error {
		collection, err := txApp.FindCollectionByNameOrId("gate_events")
		if err != nil {
			return nil
		}
		return txApp.Delete(collection)
	})
}
