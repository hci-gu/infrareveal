package migrations

import (
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	m "github.com/pocketbase/pocketbase/migrations"
)

func init() {
	m.Register(func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err != nil {
			return err
		}
		if sessions.Fields.GetByName("started_at") == nil {
			sessions.Fields.Add(&core.DateField{Name: "started_at"})
		}
		if sessions.Fields.GetByName("ended_at") == nil {
			sessions.Fields.Add(&core.DateField{Name: "ended_at"})
		}
		ensureRevisionFields(sessions)
		sessions.AddIndex("idx_sessions_active_started", false, "active, started_at", "")
		if err := txApp.Save(sessions); err != nil {
			return err
		}

		revisionCollections := []string{
			"clients", "flows", "dns_queries", "flow_attributions", "activity_episodes",
			"flow_associations", "flow_activity_chunks", "flow_activity_windows",
			"flow_activity_status", "destinations", "routes",
		}
		for _, name := range revisionCollections {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err != nil {
				return err
			}
			ensureRevisionFields(collection)
			if err := txApp.Save(collection); err != nil {
				return err
			}
		}

		indexSpecs := []struct {
			collection string
			name       string
			columns    string
		}{
			{"flows", "idx_flows_session_start", "session, start"},
			{"flows", "idx_flows_session_last_seen", "session, last_seen"},
			{"dns_queries", "idx_dns_session_timestamp", "session, timestamp"},
			{"activity_episodes", "idx_activity_episodes_session_start", "session, start"},
			{"activity_episodes", "idx_activity_episodes_session_last_seen", "session, last_seen"},
			{"routes", "idx_routes_session_socket", "session, destination_ip, destination_port, protocol"},
		}
		for _, spec := range indexSpecs {
			collection, err := txApp.FindCollectionByNameOrId(spec.collection)
			if err != nil {
				return err
			}
			collection.AddIndex(spec.name, false, spec.columns, "")
			if err := txApp.Save(collection); err != nil {
				return err
			}
		}

		records, err := txApp.FindAllRecords("sessions")
		if err != nil {
			return err
		}
		for _, record := range records {
			if record.GetDateTime("started_at").IsZero() {
				started := record.GetDateTime("created").Time()
				if flows, findErr := txApp.FindRecordsByFilter("flows", "session={:session}", "start", 1, 0, dbx.Params{"session": record.Id}); findErr == nil && len(flows) > 0 {
					candidate := flows[0].GetDateTime("start").Time()
					if !candidate.IsZero() && (started.IsZero() || candidate.Before(started)) {
						started = candidate
					}
				}
				if started.IsZero() {
					started = time.Now().UTC()
				}
				record.Set("started_at", started)
			}
			if !record.GetBool("active") && record.GetDateTime("ended_at").IsZero() {
				ended := record.GetDateTime("updated").Time()
				if flows, findErr := txApp.FindRecordsByFilter("flows", "session={:session}", "-last_seen", 1, 0, dbx.Params{"session": record.Id}); findErr == nil && len(flows) > 0 {
					candidate := flows[0].GetDateTime("last_seen").Time()
					if candidate.After(ended) {
						ended = candidate
					}
				}
				if ended.IsZero() {
					ended = time.Now().UTC()
				}
				record.Set("ended_at", ended)
			}
			if err := txApp.Save(record); err != nil {
				return err
			}
		}
		return nil
	}, func(txApp core.App) error {
		sessions, err := txApp.FindCollectionByNameOrId("sessions")
		if err == nil {
			sessions.RemoveIndex("idx_sessions_active_started")
			sessions.Fields.RemoveByName("started_at")
			sessions.Fields.RemoveByName("ended_at")
			sessions.Fields.RemoveByName("created")
			sessions.Fields.RemoveByName("updated")
			if err := txApp.Save(sessions); err != nil {
				return err
			}
		}

		for _, name := range []string{
			"clients", "flows", "dns_queries", "flow_attributions", "activity_episodes",
			"flow_associations", "flow_activity_chunks", "flow_activity_windows",
			"flow_activity_status", "destinations", "routes",
		} {
			collection, err := txApp.FindCollectionByNameOrId(name)
			if err != nil {
				continue
			}
			collection.Fields.RemoveByName("created")
			collection.Fields.RemoveByName("updated")
			if err := txApp.Save(collection); err != nil {
				return err
			}
		}

		indexSpecs := []struct {
			collection string
			name       string
		}{
			{"flows", "idx_flows_session_start"},
			{"flows", "idx_flows_session_last_seen"},
			{"dns_queries", "idx_dns_session_timestamp"},
			{"activity_episodes", "idx_activity_episodes_session_start"},
			{"activity_episodes", "idx_activity_episodes_session_last_seen"},
			{"routes", "idx_routes_session_socket"},
		}
		for _, spec := range indexSpecs {
			collection, err := txApp.FindCollectionByNameOrId(spec.collection)
			if err != nil {
				continue
			}
			collection.RemoveIndex(spec.name)
			if err := txApp.Save(collection); err != nil {
				return err
			}
		}
		return nil
	})
}

func ensureRevisionFields(collection *core.Collection) {
	if collection.Fields.GetByName("created") == nil {
		collection.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true})
	}
	if collection.Fields.GetByName("updated") == nil {
		collection.Fields.Add(&core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	}
}
