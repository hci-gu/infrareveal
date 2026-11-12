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

	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
)

const (
	defaultPageSize = 500
	maxPageSize     = 1000
	maxWindowMS     = int64(30 * time.Minute / time.Millisecond)
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
	snapshots []*pageSnapshot
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
	order                string
	compact              bool
}

type pageCursor struct {
	Revision    int64  `json:"r"`
	Offset      int    `json:"o"`
	RouteOffset int    `json:"ro,omitempty"`
	From        int64  `json:"f"`
	To          int64  `json:"t"`
	Resolution  int64  `json:"s"`
	Block       string `json:"b,omitempty"`
	Snapshot    string `json:"x,omitempty"`
	Order       string `json:"order,omitempty"`
	Compact     bool   `json:"compact,omitempty"`
	Phase       int    `json:"phase,omitempty"`
	Last        string `json:"last,omitempty"`
	Client      string `json:"client,omitempty"`
	Service     string `json:"service,omitempty"`
	Destination string `json:"destination,omitempty"`
	Time        int64  `json:"time,omitempty"`
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
	q := Query{resolution: 50, limit: defaultPageSize, block: v.Get("block"), cursor: v.Get("cursor"), compact: v.Get("compact") == "true"}
	if !mapWindow {
		switch v.Get("order") {
		case "", "oldest":
		case "latest":
			q.order = "latest"
		default:
			return Query{}, fmt.Errorf("block order must be oldest or latest")
		}
	}
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
	if err = json.Unmarshal(payload, &cursor); err != nil || cursor.Offset < 0 || cursor.Offset > 1000000 || cursor.RouteOffset < 0 || cursor.RouteOffset > 1000000 || cursor.From != q.from || cursor.To != q.to || cursor.Resolution != q.resolution || cursor.Block != q.block || cursor.Order != q.order || cursor.Compact != q.compact {
		return 0, fmt.Errorf("%w: cursor does not match this request", ErrInvalidQuery)
	}
	if cursor.Revision != revision {
		return 0, ErrRevisionChanged
	}
	return cursor.Offset, nil
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

func (r *Reader) Block(session, id string) (data.ActivityBlock, error) {
	record, err := r.app.FindRecordById("activity_blocks", id)
	if err != nil {
		return data.ActivityBlock{}, err
	}
	if record.GetString("session") != session {
		return data.ActivityBlock{}, ErrSessionNotFound
	}
	return data.Decode[data.ActivityBlock](record)
}
