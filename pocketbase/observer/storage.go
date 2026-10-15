package observer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"time"
)

var errStaleFlush = errors.New("capture epoch or generation was superseded")

func beginCapture(app core.App, session, epoch string) (data.Session, error) {
	var s data.Session
	err := app.RunInTransaction(func(tx core.App) error {
		record, err := tx.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		s, err = data.Decode[data.Session](record)
		if err != nil {
			return err
		}
		if _, err = tx.DB().NewQuery("UPDATE traffic_chunks SET sealed=1 WHERE session={:s} AND sealed=0").Bind(dbx.Params{"s": session}).Execute(); err != nil {
			return err
		}
		s.Capture.Epoch = epoch
		s.Capture.Generation = 0
		s.Capture.Running = false
		s.Capture.Quality = "unknown"
		return writeCaptureHealth(tx, session, s.Capture)
	})
	return s, err
}

func writeCaptureHealth(app core.App, session string, h data.CaptureHealth) error {
	encoded, err := json.Marshal(h)
	if err != nil {
		return err
	}
	_, err = app.DB().NewQuery("UPDATE sessions SET capture={:capture}, revision=revision+1 WHERE id={:s}").Bind(dbx.Params{"capture": string(encoded), "s": session}).Execute()
	return err
}

// persistCapture atomically replaces the provisional epoch tail and its
// confirmed coverage. The session fence survives deleted chunks, so an older
// retry cannot resurrect a group removed by attribution or retention.
func persistCapture(app core.App, session, epoch string, generation int64, chunks []data.TrafficChunk, destinations map[string]data.Destination, coverage []data.CaptureInterval, health data.CaptureHealth) (int64, error) {
	var floor int64
	err := app.RunInTransaction(func(tx core.App) error {
		record, err := tx.FindRecordById("sessions", session)
		if err != nil {
			return err
		}
		s, err := data.Decode[data.Session](record)
		if err != nil {
			return err
		}
		floor = max(s.StartedMS, s.RetainedFromMS)
		if s.Capture.Epoch != epoch || s.Capture.Generation >= generation {
			return errStaleFlush
		}
		// Keep sealed history immutable, including a previous capture epoch.
		if _, err = tx.DB().NewQuery("DELETE FROM traffic_chunks WHERE session={:s} AND capture_epoch={:e} AND sealed=0").Bind(dbx.Params{"s": session, "e": epoch}).Execute(); err != nil {
			return err
		}
		saved := map[string]bool{}
		for _, c := range chunks {
			if c.StartMS+c.ChunkMS <= floor {
				continue
			}
			c.Samples = clipSamples(c, floor)
			if len(c.Samples) == 0 {
				continue
			}
			if c.Session != session || c.CaptureEpoch != epoch || c.Generation != generation {
				return fmt.Errorf("invalid capture batch")
			}
			if r, err := tx.FindRecordById("traffic_chunks", c.ID); err == nil && r.GetBool("sealed") {
				continue
			} else if err != nil && !errors.Is(err, sql.ErrNoRows) {
				return err
			}
			if !saved[c.DestinationID] {
				d, ok := destinations[c.DestinationID]
				if !ok {
					return fmt.Errorf("missing destination snapshot %s", c.DestinationID)
				}
				if _, err := tx.FindRecordById("destinations", d.ID); errors.Is(err, sql.ErrNoRows) {
					if _, err = data.Write(tx, "destinations", d); err != nil {
						return err
					}
				} else if err != nil {
					return err
				}
				saved[d.ID] = true
			}
			if _, err = data.Write(tx, "traffic_chunks", c); err != nil {
				return err
			}
		}
		for _, c := range coverage {
			if c.EndMS > max(c.StartMS, floor) {
				c.StartMS = max(c.StartMS, floor)
				if _, err = data.Write(tx, "capture_intervals", c); err != nil {
					return err
				}
			}
		}
		health.Epoch = epoch
		health.Generation = generation
		health.Dropped += s.Capture.Dropped
		health.ConfirmedMS = max(s.Capture.ConfirmedMS, health.ConfirmedMS)
		return writeCaptureHealth(tx, session, health)
	})
	return floor, err
}

// Store complete source buckets. Retention rounds up to a bucket boundary;
// keeping partial bucket counts would let a later flush count them twice.
func clipSamples(c data.TrafficChunk, floor int64) []data.Sample {
	samples := make([]data.Sample, 0, len(c.Samples))
	for _, s := range c.Samples {
		if c.StartMS+s[0] >= floor {
			samples = append(samples, s)
		}
	}
	return samples
}

func diagnosticFlow(a *aggregate, f *connection) map[string]any {
	return map[string]any{"id": data.ID(a.epoch, f.id), "session": a.session, "flow_key": f.tuple.Key(), "client_id": f.clientID, "client_ip": f.tuple.ClientIP.String(), "destination_ip": f.tuple.RemoteIP.String(), "source_port": int(f.tuple.ClientPort), "destination_port": int(f.tuple.RemotePort), "protocol": f.tuple.Protocol, "start_ms": f.started, "last_ms": f.last, "sent": f.sent, "received": f.received, "state": map[bool]string{true: "closed", false: "active"}[f.closed], "evidence": f.evidence}
}

type diagnosticWrite struct {
	collection string
	session    string
	value      any
	queued     time.Time
}
