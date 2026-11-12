package observer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"slices"
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
func persistCapture(app core.App, session, epoch string, generation int64, chunks []data.TrafficChunk, destinations map[string]data.Destination, coverage []data.CaptureInterval, health data.CaptureHealth, caches ...*captureWriteCache) (int64, error) {
	var floor int64
	var cache *captureWriteCache
	if len(caches) > 0 {
		cache = caches[0]
	}
	next := map[string]data.TrafficChunk{}
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
		// Replace only changed provisional facts. Rewriting every row through
		// PocketBase hooks and deleting the entire tail amplified each flush by
		// thousands of redundant reads, validations and index writes.
		var previous []string
		if err := tx.DB().Select("id").From("traffic_chunks").Where(dbx.NewExp("session={:s} AND capture_epoch={:e} AND sealed=0", dbx.Params{"s": session, "e": epoch})).Column(&previous); err != nil {
			return err
		}
		retained := make(map[string]bool, len(chunks))
		write := tx.DB().NewQuery(trafficUpsert).Prepare()
		defer write.Close()
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
			retained[c.ID] = true
			if cache != nil {
				if !c.Sealed {
					next[c.ID] = c
				}
				if old, ok := cache.chunks[c.ID]; ok && sameCapturedChunk(old, c) {
					continue
				}
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
			samples, err := json.Marshal(c.Samples)
			if err != nil {
				return err
			}
			evidence, err := json.Marshal(c.Evidence)
			if err != nil {
				return err
			}
			if _, err = write.Bind(dbx.Params{"id": c.ID, "session": c.Session, "capture_epoch": c.CaptureEpoch, "client_id": c.ClientID, "client_ip": c.ClientIP, "service_key": c.ServiceKey, "service_label": c.ServiceLabel, "destination_id": c.DestinationID, "destination_ip": c.DestinationIP, "protocol": c.Protocol, "destination_port": c.DestinationPort, "network_epoch": c.NetworkEpoch, "start_ms": c.StartMS, "bucket_ms": c.BucketMS, "chunk_ms": c.ChunkMS, "generation": c.Generation, "sealed": c.Sealed, "evidence": string(evidence), "samples": string(samples)}).Execute(); err != nil {
				return err
			}
			retained[c.ID] = true
		}
		for _, id := range previous {
			if !retained[id] {
				if _, err := tx.DB().Delete("traffic_chunks", dbx.HashExp{"id": id, "sealed": false}).Execute(); err != nil {
					return err
				}
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
	if err == nil && cache != nil {
		cache.chunks = next
	}
	return floor, err
}

// Store complete source buckets. Retention rounds up to a bucket boundary;
// keeping partial bucket counts would let a later flush count them twice.
func clipSamples(c data.TrafficChunk, floor int64) []data.Sample {
	if len(c.Samples) == 0 || c.StartMS+c.Samples[0][0] >= floor {
		return c.Samples
	}
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

// This cache advances only after the atomic commit and retains only the
// correction tail. Retention clipping is applied before comparing, and a new
// session/epoch starts with an empty cache. The database generation fence still
// rejects stale writers before any cache decision.
type captureWriteCache struct{ chunks map[string]data.TrafficChunk }

func sameCapturedChunk(a, b data.TrafficChunk) bool {
	return a.ID == b.ID && a.Session == b.Session && a.CaptureEpoch == b.CaptureEpoch && a.Evidence == b.Evidence && a.Sealed == b.Sealed && a.ServiceLabel == b.ServiceLabel && a.ClientIP == b.ClientIP && a.BucketMS == b.BucketMS && a.ChunkMS == b.ChunkMS && slices.Equal(a.Samples, b.Samples)
}

const trafficUpsert = `INSERT INTO traffic_chunks (id,session,capture_epoch,client_id,client_ip,service_key,service_label,destination_id,destination_ip,protocol,destination_port,network_epoch,start_ms,bucket_ms,chunk_ms,generation,sealed,evidence,samples) VALUES ({:id},{:session},{:capture_epoch},{:client_id},{:client_ip},{:service_key},{:service_label},{:destination_id},{:destination_ip},{:protocol},{:destination_port},{:network_epoch},{:start_ms},{:bucket_ms},{:chunk_ms},{:generation},{:sealed},{:evidence},{:samples}) ON CONFLICT(id) DO UPDATE SET generation=excluded.generation,sealed=excluded.sealed,evidence=excluded.evidence,samples=excluded.samples,service_label=excluded.service_label,client_ip=excluded.client_ip WHERE traffic_chunks.sealed=0 AND (traffic_chunks.samples!=excluded.samples OR traffic_chunks.evidence!=excluded.evidence OR traffic_chunks.sealed!=excluded.sealed OR traffic_chunks.service_label!=excluded.service_label OR traffic_chunks.client_ip!=excluded.client_ip)`
