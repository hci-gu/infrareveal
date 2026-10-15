// Package timeline exposes bounded, revision-consistent product windows.
package timeline

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/routing"
)

const (
	defaultPageSize   = 500
	maxPageSize       = 1000
	maxWindowMS       = int64(30 * time.Minute / time.Millisecond)
	maxContextRecords = 4000
	maxResponseBytes  = 8 * 1024 * 1024
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrRevisionChanged = errors.New("session changed; restart this window request")
	ErrWindowTooLarge  = errors.New("window exceeds response limits; request a shorter interval")
	ErrInvalidQuery    = errors.New("invalid window query")
)

type Reader struct {
	app       core.App
	mu        sync.Mutex
	snapshots []pageSnapshot
}

func New(app core.App) *Reader { return &Reader{app: app} }

func RetentionWindow(record *core.Record) time.Duration {
	minutes := record.GetInt("retention_minutes")
	if minutes < 1 || minutes > 1440 {
		minutes = 30
	}
	return time.Duration(minutes) * time.Minute
}

func (r *Reader) Manifest(id string, now time.Time) (data.Manifest, error) {
	record, err := r.app.FindRecordById("sessions", id)
	if errors.Is(err, sql.ErrNoRows) {
		return data.Manifest{}, ErrSessionNotFound
	}
	if err != nil {
		return data.Manifest{}, err
	}
	session, err := data.Decode[data.Session](record)
	if err != nil {
		return data.Manifest{}, err
	}
	session.RetainedFromMS = max(session.StartedMS, session.RetainedFromMS)
	return data.Manifest{Session: session, ServerMS: now.UnixMilli()}, nil
}

type Query struct {
	from, to, resolution int64
	limit                int
	block                string
	cursor               string
}

type pageCursor struct {
	Revision   int64  `json:"r"`
	Offset     int    `json:"o"`
	From       int64  `json:"f"`
	To         int64  `json:"t"`
	Resolution int64  `json:"s"`
	Block      string `json:"b,omitempty"`
	Snapshot   string `json:"x,omitempty"`
}

func ParseQuery(values map[string][]string) (Query, error) {
	return parseQuery(values, true)
}

// Blocks are already aggregated and paged. A recorded session's block browser
// can span its full duration; only raw map windows need the 30-minute cap.
func ParseBlockQuery(values map[string][]string) (Query, error) {
	return parseQuery(values, false)
}

func parseQuery(values map[string][]string, mapWindow bool) (Query, error) {
	v := url.Values(values)
	q := Query{resolution: 50, limit: defaultPageSize, block: v.Get("block"), cursor: v.Get("cursor")}
	var err error
	if q.from, err = strconv.ParseInt(v.Get("from"), 10, 64); err != nil || q.from < 0 {
		return Query{}, fmt.Errorf("from must be Unix milliseconds")
	}
	if q.to, err = strconv.ParseInt(v.Get("to"), 10, 64); err != nil || q.to <= q.from {
		return Query{}, fmt.Errorf("to must be Unix milliseconds after from")
	}
	if mapWindow && q.to-q.from > maxWindowMS {
		return Query{}, fmt.Errorf("map windows are limited to 30 minutes")
	}
	if value := v.Get("resolution"); value != "" {
		q.resolution, err = strconv.ParseInt(value, 10, 64)
		if err != nil || q.resolution < 1 || q.resolution > 60000 {
			return Query{}, fmt.Errorf("resolution must be 1–60000 milliseconds")
		}
	}
	if value := v.Get("limit"); value != "" {
		q.limit, err = strconv.Atoi(value)
		if err != nil || q.limit < 1 || q.limit > maxPageSize {
			return Query{}, fmt.Errorf("limit must be 1–%d", maxPageSize)
		}
	}
	if len(q.cursor) > 2048 || len(q.block) > 100 {
		return Query{}, fmt.Errorf("invalid cursor or block")
	}
	return q, nil
}

func (q Query) offset(revision int64) (int, error) {
	if q.cursor == "" {
		return 0, nil
	}
	payload, err := base64.RawURLEncoding.DecodeString(q.cursor)
	if err != nil {
		return 0, fmt.Errorf("%w: invalid cursor", ErrInvalidQuery)
	}
	var cursor pageCursor
	if err = json.Unmarshal(payload, &cursor); err != nil || cursor.Offset < 0 || cursor.Offset > 1000000 || cursor.From != q.from || cursor.To != q.to || cursor.Resolution != q.resolution || cursor.Block != q.block {
		return 0, fmt.Errorf("%w: cursor does not match this request", ErrInvalidQuery)
	}
	if cursor.Revision != revision {
		return 0, ErrRevisionChanged
	}
	return cursor.Offset, nil
}

// A page advances only the primary traffic stream. Coverage and block summaries
// are bounded window context; there is no independent cursor per collection.
func (r *Reader) readWindow(id string, q Query) (pageSnapshot, error) {
	snapshot := pageSnapshot{session: id, kind: "map", query: queryCursor(q)}
	result := data.MapWindow{SessionID: id, ResolutionMS: q.resolution, Complete: true, Series: []data.TrafficChunk{}, Coverage: []data.CaptureInterval{}, Blocks: []data.ActivityBlock{}, Destinations: []data.Destination{}, Routes: []data.RouteEvidence{}}
	err := r.app.RunInTransaction(func(app core.App) error {
		manifest, err := New(app).Manifest(id, time.Now())
		if err != nil {
			return err
		}
		snapshot.epoch = manifest.Capture.Epoch
		result.Revision = manifest.Revision
		result.FromMS = max(q.from, manifest.RetainedFromMS)
		end := manifest.EndedMS
		if manifest.Active || end == 0 {
			end = manifest.ServerMS
		}
		result.ToMS = max(result.FromMS, min(q.to, end))
		params := dbx.Params{"session": id, "from": result.FromMS, "to": result.ToMS}
		filter := "session={:session} AND start_ms < {:to} AND start_ms + chunk_ms > {:from}"
		if q.block != "" {
			block, err := New(app).Block(id, q.block)
			if err != nil {
				return err
			}
			result.FromMS = max(result.FromMS, block.StartMS)
			result.ToMS = max(result.FromMS, min(result.ToMS, block.EndMS))
			params["from"], params["to"] = result.FromMS, result.ToMS
			params["client"], params["service"] = block.ClientID, block.ServiceKey
			filter += " AND client_id={:client} AND service_key={:service}"
		}
		if result.ToMS <= result.FromMS {
			return nil
		}
		chunks, err := data.ReadTraffic(app.DB().Select("*").From("traffic_chunks").Where(dbx.NewExp(filter, params)).OrderBy("start_ms", "id").Limit(maxContextRecords + 1))
		if err != nil {
			return err
		}
		if len(chunks) > maxContextRecords {
			return ErrWindowTooLarge
		}
		destinationIDs := map[string]bool{}
		for _, chunk := range chunks {
			// Retain fine bins at partially visible edges. Coarse bins must never
			// move future counts before the playback cursor or smear missing capture.
			chunk.Samples = visibleSamples(chunk, result.FromMS, result.ToMS)
			chunk = coarsen(chunk, q.resolution, result.FromMS, result.ToMS)
			if len(chunk.Samples) == 0 {
				continue
			}
			result.Series = append(result.Series, chunk)
			if chunk.DestinationID != "" {
				destinationIDs[chunk.DestinationID] = true
			}
		}
		result.Coverage, err = readBounded[data.CaptureInterval](app, "capture_intervals", "session={:session} && start_ms < {:to} && end_ms > {:from}", "start_ms,id", params)
		if err != nil {
			return err
		}
		for i := range result.Coverage {
			result.Coverage[i].StartMS = max(result.Coverage[i].StartMS, result.FromMS)
			result.Coverage[i].EndMS = min(result.Coverage[i].EndMS, result.ToMS)
		}
		blockFilter := "session={:session} && start_ms < {:to} && end_ms > {:from}"
		if q.block != "" {
			blockFilter += " && id={:block}"
			params["block"] = q.block
		}
		result.Blocks, err = readBounded[data.ActivityBlock](app, "activity_blocks", blockFilter, "start_ms,id", params)
		if err != nil {
			return err
		}
		if len(destinationIDs) > 0 {
			ids := make([]any, 0, len(destinationIDs))
			for destinationID := range destinationIDs {
				ids = append(ids, destinationID)
			}
			rows, err := app.FindAllRecords("destinations", dbx.In("id", ids...))
			if err != nil {
				return err
			}
			for _, row := range rows {
				destination, err := data.Decode[data.Destination](row)
				if err != nil {
					return err
				}
				result.Destinations = append(result.Destinations, destination)
			}
		}
		evidence, err := routing.QueryEvidence(app, routing.EvidenceQuery{Session: id, From: time.UnixMilli(result.FromMS), To: time.UnixMilli(result.ToMS), Limit: 1000})
		if err != nil {
			return err
		}
		if evidence.More {
			return ErrWindowTooLarge
		}
		for _, row := range evidence.Records {
			evidence, err := data.Decode[data.RouteEvidence](row)
			if err != nil {
				return err
			}
			result.Routes = append(result.Routes, evidence)
		}
		payload, err := json.Marshal(result)
		if err != nil {
			return err
		}
		snapshot.size = len(payload)
		if snapshot.size > maxResponseBytes {
			return ErrWindowTooLarge
		}
		return nil
	})
	snapshot.window, snapshot.from = result, result.FromMS
	return snapshot, err
}

// Counts are emitted when a complete source bucket is known. A cursor inside a
// 50 ms bin must not count packets that may have arrived later in that bin.
func visibleSamples(chunk data.TrafficChunk, from, to int64) []data.Sample {
	samples := make([]data.Sample, 0, len(chunk.Samples))
	for _, sample := range chunk.Samples {
		start := chunk.StartMS + sample[0]
		if start >= from && start+chunk.BucketMS <= to {
			samples = append(samples, sample)
		}
	}
	return samples
}

// Resolution is preferred: keep source bins at window/chunk edges unless every
// coarse bin can be emitted in full. Each series reports its actual bucket size.
func coarsen(chunk data.TrafficChunk, resolution, from, to int64) data.TrafficChunk {
	step := min(resolution, chunk.ChunkMS)
	if chunk.BucketMS <= 0 || step <= chunk.BucketMS || step%chunk.BucketMS != 0 || chunk.ChunkMS%step != 0 || from > chunk.StartMS || to < chunk.StartMS+chunk.ChunkMS {
		return chunk
	}
	samples := make([]data.Sample, 0, len(chunk.Samples))
	for _, sample := range chunk.Samples {
		offset := sample[0] / step * step
		if len(samples) == 0 || samples[len(samples)-1][0] != offset {
			samples = append(samples, data.Sample{offset})
		}
		for column := 1; column < len(sample); column++ {
			samples[len(samples)-1][column] += sample[column]
		}
	}
	chunk.Samples = samples
	chunk.BucketMS = step
	return chunk
}

func readBounded[T any](app core.App, collection, filter, sort string, params dbx.Params) ([]T, error) {
	rows, err := app.FindRecordsByFilter(collection, filter, sort, maxContextRecords+1, 0, params)
	if err != nil {
		return nil, err
	}
	if len(rows) > maxContextRecords {
		return nil, ErrWindowTooLarge
	}
	result := make([]T, 0, len(rows))
	for _, row := range rows {
		item, err := data.Decode[T](row)
		if err != nil {
			return nil, err
		}
		result = append(result, item)
	}
	return result, nil
}

func (r *Reader) Block(session, id string) (data.ActivityBlock, error) {
	record, err := r.app.FindRecordById("activity_blocks", id)
	if err != nil {
		return data.ActivityBlock{}, err
	}
	if record.GetString("session") != session {
		return data.ActivityBlock{}, sql.ErrNoRows
	}
	return data.Decode[data.ActivityBlock](record)
}

func (r *Reader) readBlocks(id string, q Query) (pageSnapshot, error) {
	snapshot := pageSnapshot{session: id, kind: "blocks", query: queryCursor(q), blocks: data.BlockPage{SessionID: id, Items: []data.ActivityBlock{}}}
	err := r.app.RunInTransaction(func(app core.App) error {
		manifest, err := New(app).Manifest(id, time.Now())
		if err != nil {
			return err
		}
		snapshot.blocks.Revision, snapshot.epoch = manifest.Revision, manifest.Capture.Epoch
		snapshot.from = max(q.from, manifest.RetainedFromMS)
		// A long saved range is allowed, but never an unbounded recording read.
		items, err := readBounded[data.ActivityBlock](app, "activity_blocks", "session={:session} && start_ms < {:to} && end_ms > {:from}", "start_ms,id", dbx.Params{"session": id, "from": snapshot.from, "to": q.to})
		if err != nil {
			return err
		}
		snapshot.blocks.Items = items
		payload, err := json.Marshal(snapshot.blocks)
		if err != nil {
			return err
		}
		snapshot.size = len(payload)
		if snapshot.size > maxResponseBytes {
			return ErrWindowTooLarge
		}
		return nil
	})
	return snapshot, err
}
