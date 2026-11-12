package timeline

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
)

// A short-lived WAL read snapshot pins facts across pages without taking the
// capture writer's connection or copying a whole recording into server memory.
const snapshotTTL = 60 * time.Second
const pageBytes = 2 * 1024 * 1024

type pageSnapshot struct {
	complete                 atomic.Bool
	id, session, kind, epoch string
	at                       time.Time
	from                     int64
	query                    pageCursor
	manifest                 data.Manifest
	tx                       *dbx.Tx
	cancel                   context.CancelFunc
	mu                       sync.Mutex
	timer                    *time.Timer
}

func (r *Reader) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, s := range r.snapshots {
		s.cancel()
		s.timer.Stop()
	}
	r.snapshots = nil
}

func queryCursor(q Query) pageCursor {
	return pageCursor{From: q.from, To: q.to, Resolution: q.resolution, Block: q.block, Order: q.order, Compact: q.compact}
}
func encodeCursor(c pageCursor) string {
	b, _ := json.Marshal(c)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (r *Reader) snapshot(id string, q Query, kind string) (*pageSnapshot, pageCursor, error) {
	c := queryCursor(q)
	if q.cursor != "" {
		b, err := base64.RawURLEncoding.DecodeString(q.cursor)
		if err != nil || json.Unmarshal(b, &c) != nil || c.Snapshot == "" || c.Offset < 0 || c.Phase < 0 || c.Phase > 1 {
			return nil, c, ErrInvalidQuery
		}
		r.mu.Lock()
		var found *pageSnapshot
		for _, s := range r.snapshots {
			if s.id == c.Snapshot && s.session == id && s.kind == kind && time.Since(s.at) < snapshotTTL {
				found = s
				break
			}
		}
		r.mu.Unlock()
		if found == nil {
			return nil, c, ErrRevisionChanged
		}
		if found.query != queryCursor(q) {
			return nil, c, ErrInvalidQuery
		}
		if _, err := q.offset(found.manifest.Revision); err != nil {
			return nil, c, err
		}
		if found.complete.Load() {
			return nil, c, ErrRevisionChanged
		}
		m, err := r.Manifest(id, time.Now())
		if err != nil {
			return nil, c, err
		}
		if m.RetainedFromMS > found.from || m.Capture.Epoch != found.epoch {
			return nil, c, ErrRevisionChanged
		}
		return found, c, nil
	}
	db, ok := r.app.ConcurrentDB().(*dbx.DB)
	if !ok {
		return nil, c, fmt.Errorf("timeline requires a concurrent database")
	}
	ctx, cancel := context.WithTimeout(context.Background(), snapshotTTL)
	tx, err := db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		cancel()
		return nil, c, err
	}
	fail := func(err error) (*pageSnapshot, pageCursor, error) { cancel(); _ = tx.Rollback(); return nil, c, err }
	sessions, err := readFacts[data.Session](r.app, tx, "sessions", "id={:id}", "id", dbx.Params{"id": id}, 1, 0)
	if err != nil {
		return fail(err)
	}
	if len(sessions) == 0 {
		return fail(ErrSessionNotFound)
	}
	m := data.Manifest{Session: sessions[0], ServerMS: time.Now().UnixMilli()}
	m.RetainedFromMS = max(m.StartedMS, m.RetainedFromMS)
	s := &pageSnapshot{id: data.NewID(), session: id, kind: kind, at: time.Now(), from: max(q.from, m.RetainedFromMS), query: queryCursor(q), manifest: m, epoch: m.Capture.Epoch, tx: tx, cancel: cancel}
	// Context cancellation releases the read transaction even if a browser never
	// requests its next page. No abandoned reader can pin the WAL indefinitely.
	s.timer = time.AfterFunc(snapshotTTL, cancel)
	r.mu.Lock()
	kept := r.snapshots[:0]
	for _, old := range r.snapshots {
		if !old.complete.Load() && time.Since(old.at) < snapshotTTL {
			kept = append(kept, old)
		} else {
			old.cancel()
			old.timer.Stop()
		}
	}
	r.snapshots = append(kept, s)
	for len(r.snapshots) > 8 {
		r.snapshots[0].cancel()
		r.snapshots[0].timer.Stop()
		r.snapshots = r.snapshots[1:]
	}
	r.mu.Unlock()
	c.Snapshot = s.id
	c.Revision = m.Revision
	return s, c, nil
}

// Read bounded scalar/JSON records through the pinned connection. PocketBase
// field conversion keeps null geography, booleans and 64-bit counters intact.
func readFacts[T any](app core.App, db dbx.Builder, table, filter, order string, params dbx.Params, limit, offset int) ([]T, error) {
	collection, err := app.FindCachedCollectionByNameOrId(table)
	if err != nil {
		return nil, err
	}
	var rows []dbx.NullStringMap
	err = db.Select("*").From(table).Where(dbx.NewExp(filter, params)).OrderBy(strings.Split(order, "|")...).Limit(int64(limit)).Offset(int64(offset)).All(&rows)
	if err != nil {
		return nil, err
	}
	result := make([]T, 0, len(rows))
	for _, row := range rows {
		record := core.NewRecord(collection)
		for key, value := range row {
			if value.Valid {
				record.Set(key, value.String)
			}
		}
		value, err := data.Decode[T](record)
		if err != nil {
			return nil, err
		}
		result = append(result, value)
	}
	return result, nil
}

func (r *Reader) Window(id string, q Query) (data.MapWindow, error) {
	s, c, err := r.snapshot(id, q, "map")
	if err != nil {
		return data.MapWindow{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	end := s.manifest.EndedMS
	if s.manifest.Active || end == 0 {
		end = s.manifest.ServerMS
	}
	result := data.MapWindow{SessionID: id, Revision: s.manifest.Revision, FromMS: s.from, ToMS: max(s.from, min(q.to, end)), ResolutionMS: q.resolution, Series: []data.TrafficChunk{}, Coverage: []data.CaptureInterval{}, Blocks: []data.ActivityBlock{}, Routes: []data.RouteEvidence{}, Destinations: []data.Destination{}}
	params := dbx.Params{"session": id, "from": result.FromMS, "to": result.ToMS}
	params["scanFrom"] = result.FromMS - 10000
	filter := "session={:session} AND start_ms > {:scanFrom} AND start_ms < {:to} AND start_ms + chunk_ms > {:from}"
	if q.block != "" {
		blocks, err := readFacts[data.ActivityBlock](r.app, s.tx, "activity_blocks", "session={:session} AND id={:block}", "id", dbx.Params{"session": id, "block": q.block}, 1, 0)
		if err != nil {
			return result, err
		}
		if len(blocks) == 0 {
			return result, ErrSessionNotFound
		}
		block := blocks[0]
		result.FromMS = max(result.FromMS, block.StartMS)
		result.ToMS = min(result.ToMS, block.EndMS)
		params["from"], params["to"], params["client"], params["service"] = result.FromMS, result.ToMS, block.ClientID, block.ServiceKey
		filter += " AND client_id={:client} AND service_key={:service}"
	}
	if result.ToMS <= result.FromMS {
		s.complete.Store(true)
		s.cancel()
		s.timer.Stop()
		result.Complete = true
		return result, nil
	}
	// Pages advance all bounded contexts together. Offset cursors are pinned to a
	// read snapshot; traffic uses the indexed (start_ms,id) keyset on dense pages.
	limit := min(q.limit, 500)
	more := false
	if c.Phase == 0 {
		var err error
		result.Series, more, err = readTrafficPage(s.tx, q, &c, filter, params, result.FromMS, result.ToMS)
		if err != nil {
			return result, err
		}
		if !more {
			c.Phase = 1
		}
	}

	// Context is independently paged so thousands of activity blocks or capture
	// interruptions cannot reintroduce a whole-window limit.
	coverage, err := readFacts[data.CaptureInterval](r.app, s.tx, "capture_intervals", "session={:session} AND start_ms < {:to} AND end_ms > {:from}", "start_ms|id", params, limit+1, c.Offset)
	if err != nil {
		return result, err
	}
	if len(coverage) > limit {
		more = true
		coverage = coverage[:limit]
	}
	for i := range coverage {
		coverage[i].StartMS = max(coverage[i].StartMS, result.FromMS)
		coverage[i].EndMS = min(coverage[i].EndMS, result.ToMS)
	}
	result.Coverage = coverage
	if !q.compact {
		bf := "session={:session} AND start_ms < {:to} AND end_ms > {:from}"
		if q.block != "" {
			bf += " AND id={:block}"
			params["block"] = q.block
		}
		blocks, err := readFacts[data.ActivityBlock](r.app, s.tx, "activity_blocks", bf, "start_ms|id", params, limit+1, c.Offset)
		if err != nil {
			return result, err
		}
		if len(blocks) > limit {
			more = true
			blocks = blocks[:limit]
		}
		result.Blocks = blocks
		// Route JSON can be much larger than a traffic row. Bound decoding as
		// well as the eventual response, independently of the traffic page size.
		routeLimit := min(limit, 16)
		routes, err := readFacts[data.RouteEvidence](r.app, s.tx, "route_evidence", routeFilter, "available_ms|id", params, routeLimit+1, c.RouteOffset)
		if err != nil {
			return result, err
		}
		routeBytes, count := 0, 0
		for _, route := range routes {
			encoded, err := json.Marshal(route)
			if err != nil {
				return result, err
			}
			if count == routeLimit || (count > 0 && routeBytes+len(encoded) > pageBytes) {
				break
			}
			routeBytes += len(encoded)
			count++
		}
		if count < len(routes) {
			more = true
		}
		result.Routes = routes[:count]
		c.RouteOffset += count
	}
	ids := map[string]bool{}
	for _, chunk := range result.Series {
		if chunk.DestinationID != "" {
			ids[chunk.DestinationID] = true
		}
	}
	if len(ids) > 0 {
		values := make([]any, 0, len(ids))
		for key := range ids {
			values = append(values, key)
		}
		query := s.tx.Select("*").From("destinations").Where(dbx.In("id", values...))
		if err = query.All(&result.Destinations); err != nil {
			return result, err
		}
	}
	result.Complete = !more
	if !more {
		s.complete.Store(true)
		s.cancel()
		s.timer.Stop()
	}
	if more {
		c.Offset += limit
		result.NextCursor = encodeCursor(c)
	}
	return result, nil
}

const routeFilter = `session={:session} AND available_ms < {:to} AND (
 kind='network_invalidated' OR available_ms >= {:from} OR NOT EXISTS (
 SELECT 1 FROM route_evidence newer WHERE newer.session=route_evidence.session
 AND newer.kind='path' AND newer.network_epoch=route_evidence.network_epoch
 AND newer.binding_key=route_evidence.binding_key AND newer.available_ms < {:from}
 AND (newer.available_ms>route_evidence.available_ms OR (newer.available_ms=route_evidence.available_ms AND newer.id>route_evidence.id))))`

func (r *Reader) Blocks(id string, q Query) (data.BlockPage, error) {
	s, c, err := r.snapshot(id, q, "blocks")
	if err != nil {
		return data.BlockPage{}, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	params := dbx.Params{"session": id, "from": s.from, "to": q.to}
	order := "start_ms|id"
	if q.order == "latest" {
		order = "MIN(end_ms," + fmt.Sprint(q.to) + ") DESC|id DESC"
	}
	items, err := readFacts[data.ActivityBlock](r.app, s.tx, "activity_blocks", "session={:session} AND start_ms < {:to} AND end_ms > {:from}", order, params, q.limit+1, c.Offset)
	if err != nil {
		return data.BlockPage{}, err
	}
	result := data.BlockPage{SessionID: id, Revision: s.manifest.Revision, Items: items}
	if len(items) <= q.limit {
		s.complete.Store(true)
		s.cancel()
		s.timer.Stop()
	}
	if len(items) > q.limit {
		result.Items = items[:q.limit]
		c.Offset += q.limit
		result.NextCursor = encodeCursor(c)
	}
	return result, nil
}

// A page aggregates ordered bindings while scanning bounded source batches.
// Source work, output records and bytes have separate limits. Cursor state
// describes the last consumed source row, so even one huge binding can continue.
func readTrafficPage(db dbx.Builder, q Query, c *pageCursor, filter string, params dbx.Params, from, to int64) ([]data.TrafficChunk, bool, error) {
	result := []data.TrafficChunk{}
	groups := map[string]int{}
	used, scanned := 0, 0
	for scanned < 8192 {
		predicate := filter
		order := []string{"start_ms", "id"}
		if q.compact {
			order = []string{"client_id", "service_key", "destination_id", "start_ms", "id"}
		}
		if c.Last != "" {
			params["lastTime"], params["lastID"] = c.Time, c.Last
			if q.compact {
				params["lastClient"], params["lastService"], params["lastDestination"] = c.Client, c.Service, c.Destination
				predicate += " AND (client_id,service_key,destination_id,start_ms,id) > ({:lastClient},{:lastService},{:lastDestination},{:lastTime},{:lastID})"
			} else {
				predicate += " AND (start_ms,id) > ({:lastTime},{:lastID})"
			}
		}
		batch := min(1024, q.limit)
		// Pin the compact ordering index: SQLite otherwise sorts the entire
		// time range again for every 256-row source batch.
		var query interface{ All(any) error }
		if q.compact {
			query = db.NewQuery("SELECT * FROM traffic_chunks INDEXED BY traffic_binding_time WHERE " + predicate + " ORDER BY " + strings.Join(order, ",") + " LIMIT " + fmt.Sprint(batch)).Bind(params)
		} else {
			query = db.Select("*").From("traffic_chunks").Where(dbx.NewExp(predicate, params)).OrderBy(order...).Limit(int64(batch))
		}
		chunks, err := data.ReadTraffic(query)
		if err != nil {
			return nil, false, err
		}
		for _, chunk := range chunks {
			sourceTime, sourceID := chunk.StartMS, chunk.ID
			chunk.Samples = visibleSamples(chunk, from, to)
			chunk = coarsen(chunk, q.resolution, from, to)
			key := chunk.ID
			if q.compact {
				evidence, _ := json.Marshal(chunk.Evidence)
				key = data.ID(string(evidence), chunk.CaptureEpoch, chunk.ClientID, chunk.ServiceKey, chunk.DestinationID, chunk.DestinationIP, chunk.Protocol, fmt.Sprint(chunk.DestinationPort), chunk.NetworkEpoch, fmt.Sprint(chunk.BucketMS))
			}
			index, exists := groups[key]
			additional := 0
			if exists {
				samples, _ := json.Marshal(chunk.Samples)
				additional = len(samples) + 16*len(chunk.Samples)
			} else {
				encoded, _ := json.Marshal(chunk)
				additional = len(encoded)
			}
			if len(result) > 0 && (used+additional > pageBytes || (!exists && len(result) >= q.limit)) {
				return result, true, nil
			}
			used += additional
			scanned++
			c.Time, c.Last, c.Client, c.Service, c.Destination = sourceTime, sourceID, chunk.ClientID, chunk.ServiceKey, chunk.DestinationID
			if len(chunk.Samples) == 0 {
				continue
			}
			if exists {
				target := &result[index]
				for _, sample := range chunk.Samples {
					sample[0] += chunk.StartMS - target.StartMS
					target.Samples = append(target.Samples, sample)
				}
				target.ChunkMS = max(target.ChunkMS, chunk.StartMS+chunk.ChunkMS-target.StartMS)
				target.Sealed = target.Sealed && chunk.Sealed
			} else {
				groups[key] = len(result)
				result = append(result, chunk)
			}
		}
		if len(chunks) < batch {
			return result, false, nil
		}
	}
	return result, true, nil
}
