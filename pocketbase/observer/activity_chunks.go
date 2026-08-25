package observer

import (
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
)

type activityPersistResult uint8

const (
	activityPersisted activityPersistResult = iota + 1
	activityFlowPending
)

func persistActivityChunk(app core.App, snapshot ActivityChunkSnapshot) (activityPersistResult, error) {
	flow, err := app.FindFirstRecordByFilter(
		"flows",
		"session={:session} && flow_key={:flow_key}",
		dbx.Params{"session": snapshot.SessionID, "flow_key": snapshot.FlowKey},
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return activityFlowPending, nil
		}
		return 0, err
	}

	record, err := app.FindFirstRecordByFilter(
		"flow_activity_chunks",
		"chunk_key={:chunk_key}",
		dbx.Params{"chunk_key": snapshot.Key},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return 0, err
		}
		collection, err := app.FindCollectionByNameOrId("flow_activity_chunks")
		if err != nil {
			return 0, err
		}
		record = core.NewRecord(collection)
		record.Set("session", snapshot.SessionID)
		record.Set("flow", flow.Id)
		record.Set("chunk_key", snapshot.Key)
		record.Set("flow_key", snapshot.FlowKey)
		record.Set("chunk_start", snapshot.ChunkStart.UTC().Format(time.RFC3339Nano))
	}

	samples := make([][]int64, 0, len(snapshot.Samples))
	for _, sample := range snapshot.Samples {
		samples = append(samples, []int64{
			sample.OffsetMS,
			sample.PayloadBytesOut,
			sample.PayloadBytesIn,
			sample.PacketsOut,
			sample.PacketsIn,
		})
	}
	record.Set("bucket_ms", snapshot.BucketMS)
	record.Set("chunk_ms", snapshot.ChunkMS)
	record.Set("samples", map[string]any{
		"version":   1,
		"bucket_ms": snapshot.BucketMS,
		"chunk_ms":  snapshot.ChunkMS,
		"samples":   samples,
	})
	record.Set("wire_bytes_out", snapshot.WireBytesOut)
	record.Set("wire_bytes_in", snapshot.WireBytesIn)
	record.Set("payload_bytes_out", snapshot.PayloadBytesOut)
	record.Set("payload_bytes_in", snapshot.PayloadBytesIn)
	record.Set("packets_out", snapshot.PacketsOut)
	record.Set("packets_in", snapshot.PacketsIn)
	record.Set("tcp_flags_out", int(snapshot.TCPFlagsOut))
	record.Set("tcp_flags_in", int(snapshot.TCPFlagsIn))
	record.Set("capture_complete", snapshot.CaptureComplete)
	record.Set("dropped_events", snapshot.DroppedEvents)
	record.Set("updated_at_source", snapshot.UpdatedAtSource.UTC().Format(time.RFC3339Nano))
	if err := app.Save(record); err != nil {
		return 0, err
	}
	return activityPersisted, nil
}

func upsertActivityCaptureWindow(
	app core.App,
	sessionID string,
	windowStart time.Time,
	windowDuration time.Duration,
	running bool,
	droppedEvents int64,
	lastError string,
) error {
	if sessionID == "" {
		return nil
	}
	windowKey := activityWindowKey(sessionID, windowStart)
	record, err := app.FindFirstRecordByFilter(
		"flow_activity_windows",
		"window_key={:window_key}",
		dbx.Params{"window_key": windowKey},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		collection, err := app.FindCollectionByNameOrId("flow_activity_windows")
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("session", sessionID)
		record.Set("window_key", windowKey)
		record.Set("window_start", windowStart.UTC().Format(time.RFC3339Nano))
	}
	record.Set("window_ms", int(windowDuration/time.Millisecond))
	record.Set("capture_running", running)
	record.Set("capture_complete", running && droppedEvents == 0 && lastError == "")
	record.Set("dropped_events", droppedEvents)
	record.Set("last_error", lastError)
	return app.Save(record)
}

func activityWindowKey(sessionID string, start time.Time) string {
	return sessionID + "|" + start.UTC().Format(time.RFC3339Nano)
}

type ActivityCaptureStatus struct {
	SessionID     string
	Interface     string
	Enabled       bool
	Running       bool
	DroppedEvents int64
	LastError     string
	LastEventAt   time.Time
}

func upsertActivityCaptureStatus(app core.App, status ActivityCaptureStatus) error {
	if status.SessionID == "" {
		return nil
	}
	record, err := app.FindFirstRecordByFilter(
		"flow_activity_status",
		"session={:session}",
		dbx.Params{"session": status.SessionID},
	)
	if err != nil {
		if !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		collection, err := app.FindCollectionByNameOrId("flow_activity_status")
		if err != nil {
			return err
		}
		record = core.NewRecord(collection)
		record.Set("session", status.SessionID)
	}
	record.Set("interface", status.Interface)
	record.Set("enabled", status.Enabled)
	record.Set("running", status.Running)
	record.Set("dropped_events", status.DroppedEvents)
	record.Set("last_error", status.LastError)
	if !status.LastEventAt.IsZero() {
		record.Set("last_event_at", status.LastEventAt.UTC().Format(time.RFC3339Nano))
	}
	record.Set("reported_at", time.Now().UTC().Format(time.RFC3339Nano))
	return app.Save(record)
}

func pruneExpiredActivityChunks(app *pocketbase.PocketBase, cutoff time.Time, limit int) (int, error) {
	if limit <= 0 {
		limit = 200
	}
	records, err := app.FindRecordsByFilter(
		"flow_activity_chunks",
		"chunk_start < {:cutoff}",
		"chunk_start",
		limit*5,
		0,
		dbx.Params{"cutoff": cutoff.UTC().Format(time.RFC3339Nano)},
	)
	if err != nil {
		return 0, err
	}
	deleted := 0
	for _, record := range records {
		if deleted >= limit {
			break
		}
		sessionID := record.GetString("session")
		session, err := app.FindRecordById("sessions", sessionID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return deleted, err
		}
		if session != nil && session.GetBool("active") {
			continue
		}
		if err := app.Delete(record); err != nil {
			return deleted, fmt.Errorf("delete expired flow activity chunk: %w", err)
		}
		deleted++
	}
	remaining := limit - deleted
	if remaining <= 0 {
		return deleted, nil
	}
	windows, err := app.FindRecordsByFilter(
		"flow_activity_windows",
		"window_start < {:cutoff}",
		"window_start",
		remaining*5,
		0,
		dbx.Params{"cutoff": cutoff.UTC().Format(time.RFC3339Nano)},
	)
	if err != nil {
		return deleted, err
	}
	for _, record := range windows {
		if deleted >= limit {
			break
		}
		sessionID := record.GetString("session")
		session, err := app.FindRecordById("sessions", sessionID)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return deleted, err
		}
		if session != nil && session.GetBool("active") {
			continue
		}
		if err := app.Delete(record); err != nil {
			return deleted, fmt.Errorf("delete expired flow activity window: %w", err)
		}
		deleted++
	}
	return deleted, nil
}
