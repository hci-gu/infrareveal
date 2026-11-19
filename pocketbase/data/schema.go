package data

import "github.com/pocketbase/pocketbase/core"

func text(name string, max int) core.Field { return &core.TextField{Name: name, Max: max} }
func number(name string) core.Field {
	minimum, maximum := float64(0), float64(9007199254740991)
	if name == "source_port" || name == "destination_port" {
		maximum = 65535
	}
	return &core.NumberField{Name: name, OnlyInt: true, Min: &minimum, Max: &maximum}
}
func flag(name string) core.Field { return &core.BoolField{Name: name} }
func jsonField(name string, max int) core.Field {
	return &core.JSONField{Name: name, MaxSize: int64(max)}
}

// Collection reads and writes are admin-only. The bounded map API is the public
// read contract; it never exposes the probe ledger.
func NewCollection(name string, fields ...core.Field) *core.Collection {
	c := core.NewBaseCollection(name)
	c.Fields.Add(fields...)
	c.Fields.Add(&core.AutodateField{Name: "created", OnCreate: true}, &core.AutodateField{Name: "updated", OnCreate: true, OnUpdate: true})
	return c
}

func InstallCore(app core.App) error {
	sessions := NewCollection("sessions", text("name", 200), flag("active"), flag("ephemeral"), flag("demo"), number("started_ms"), number("ended_ms"), number("retention_minutes"), number("retained_from_ms"), number("revision"), jsonField("policy", 32768), jsonField("capture", 4096))
	SimulationFields(sessions)
	sessions.Fields.Add(text("network_context", 256), text("network_epoch", 128), number("block_watermark_ms"))
	chunks := NewCollection("traffic_chunks", text("session", 15), text("capture_epoch", 64), text("client_id", 128), text("client_ip", 64), text("service_key", 300), text("service_label", 300), text("destination_id", 15), text("destination_ip", 64), text("protocol", 16), number("destination_port"), text("network_epoch", 128), number("start_ms"), number("bucket_ms"), number("chunk_ms"), number("generation"), flag("sealed"), jsonField("evidence", 4096), jsonField("samples", 65536))
	chunks.AddIndex("traffic_binding_time", false, "session,client_id,service_key,destination_id,start_ms,id", "")
	chunks.AddIndex("traffic_session_time", false, "session,start_ms,id", "")
	chunks.AddIndex("traffic_session_service", false, "session,client_id,service_key,start_ms", "")
	chunks.AddIndex("traffic_destination", false, "destination_id", "")
	chunks.AddIndex("traffic_unsealed", false, "session,start_ms", "sealed = 0")
	coverage := NewCollection("capture_intervals", text("session", 15), text("capture_epoch", 64), number("start_ms"), number("end_ms"), text("quality", 32), number("dropped"), text("reason", 500))
	coverage.AddIndex("capture_session_time", false, "session,start_ms,end_ms", "")
	coverage.AddIndex("capture_session_end", false, "session,end_ms", "")
	blocks := NewCollection("activity_blocks", text("session", 15), text("client_id", 128), text("client_ip", 64), text("service_key", 300), text("service_label", 300), number("original_start_ms"), number("start_ms"), number("end_ms"), number("active_ms"), number("sent"), number("received"), text("confidence", 32), text("quality", 32), flag("provisional"), flag("clipped"), number("revision"))
	blocks.AddIndex("blocks_session_time", false, "session,start_ms,id", "")
	blocks.AddIndex("blocks_session_client_service", false, "session,client_id,service_key,end_ms", "")
	// Private projection state folds immutable bins once, without another store.
	blocks.Fields.Add(jsonField("block_prefix", 4096), flag("prefix_open"))
	blocks.AddIndex("blocks_projection_tail", false, "session,prefix_open,end_ms", "")
	blocks.AddIndex("blocks_provisional", false, "session,end_ms", "provisional = 1")
	destinations := NewCollection("destinations", text("ip", 64), text("version", 128), number("observed_ms"), text("country", 100), text("country_code", 8), text("city", 200), &core.NumberField{Name: "lat"}, &core.NumberField{Name: "lon"}, number("accuracy_km"), text("precision", 16), text("provider", 200), number("asn"), text("ptr", 300))
	destinations.AddIndex("destination_ip_version", true, "ip,version", "")
	collections := append([]*core.Collection{sessions, chunks, coverage, blocks, destinations}, routeCollections()...)
	return app.RunInTransaction(func(tx core.App) error {
		for _, c := range collections {
			if err := tx.Save(c); err != nil {
				return err
			}
		}
		return nil
	})
}

// Synthetic sessions have a durable cleanup marker and never take ownership of
// the gateway capture. Keep one live capture and at most one simulation.
func SimulationFields(sessions *core.Collection) {
	sessions.Fields.Add(number("simulation_expires_ms"))
	sessions.RemoveIndex("one_active_session")
	sessions.AddIndex("one_active_session", true, "active", "active = 1 AND simulation_expires_ms = 0")
	sessions.AddIndex("one_simulation", true, "active", "simulation_expires_ms > 0")
}
