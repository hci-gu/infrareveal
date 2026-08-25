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

		chunks, err := ensureCollection(txApp, "flow_activity_chunks", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.RelationField{Name: "flow", CollectionId: flows.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "chunk_key", Max: 800, Required: true},
			&core.TextField{Name: "flow_key", Max: 500, Required: true},
			&core.DateField{Name: "chunk_start", Required: true},
			&core.NumberField{Name: "bucket_ms", OnlyInt: true, Required: true},
			&core.NumberField{Name: "chunk_ms", OnlyInt: true, Required: true},
			&core.JSONField{Name: "samples", Required: true},
			&core.NumberField{Name: "wire_bytes_out", OnlyInt: true},
			&core.NumberField{Name: "wire_bytes_in", OnlyInt: true},
			&core.NumberField{Name: "payload_bytes_out", OnlyInt: true},
			&core.NumberField{Name: "payload_bytes_in", OnlyInt: true},
			&core.NumberField{Name: "packets_out", OnlyInt: true},
			&core.NumberField{Name: "packets_in", OnlyInt: true},
			&core.NumberField{Name: "tcp_flags_out", OnlyInt: true},
			&core.NumberField{Name: "tcp_flags_in", OnlyInt: true},
			&core.BoolField{Name: "capture_complete"},
			&core.NumberField{Name: "dropped_events", OnlyInt: true},
			&core.DateField{Name: "updated_at_source"},
		})
		if err != nil {
			return err
		}
		chunks.AddIndex("idx_flow_activity_session_flow_chunk", true, "session, flow, chunk_start", "")
		chunks.AddIndex("idx_flow_activity_chunk_key", true, "chunk_key", "")
		chunks.AddIndex("idx_flow_activity_flow_chunk", false, "flow, chunk_start", "")
		chunks.AddIndex("idx_flow_activity_session_chunk", false, "session, chunk_start", "")
		if err := txApp.Save(chunks); err != nil {
			return err
		}

		status, err := ensureCollection(txApp, "flow_activity_status", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "interface", Max: 64},
			&core.BoolField{Name: "enabled"},
			&core.BoolField{Name: "running"},
			&core.NumberField{Name: "dropped_events", OnlyInt: true},
			&core.TextField{Name: "last_error", Max: 1000},
			&core.DateField{Name: "last_event_at"},
			&core.DateField{Name: "reported_at"},
		})
		if err != nil {
			return err
		}
		status.AddIndex("idx_flow_activity_status_session", true, "session", "")
		if err := txApp.Save(status); err != nil {
			return err
		}

		windows, err := ensureCollection(txApp, "flow_activity_windows", []core.Field{
			&core.RelationField{Name: "session", CollectionId: sessions.Id, MaxSelect: 1, Required: true},
			&core.TextField{Name: "window_key", Max: 200, Required: true},
			&core.DateField{Name: "window_start", Required: true},
			&core.NumberField{Name: "window_ms", OnlyInt: true, Required: true},
			&core.BoolField{Name: "capture_running"},
			&core.BoolField{Name: "capture_complete"},
			&core.NumberField{Name: "dropped_events", OnlyInt: true},
			&core.TextField{Name: "last_error", Max: 1000},
		})
		if err != nil {
			return err
		}
		windows.AddIndex("idx_flow_activity_windows_session_start", true, "session, window_start", "")
		windows.AddIndex("idx_flow_activity_windows_key", true, "window_key", "")
		return txApp.Save(windows)
	}, func(txApp core.App) error {
		for _, name := range []string{"flow_activity_chunks", "flow_activity_windows", "flow_activity_status"} {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err == nil {
				if err := txApp.Delete(collection); err != nil {
					return err
				}
			}
		}
		return nil
	})
}
