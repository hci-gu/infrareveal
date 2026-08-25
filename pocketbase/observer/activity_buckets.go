package observer

import (
	"math"
	"sort"
	"time"
)

type ActivityBucket struct {
	OffsetMS        int64
	PayloadBytesOut int64
	PayloadBytesIn  int64
	PacketsOut      int64
	PacketsIn       int64
}

type ActivityChunkSnapshot struct {
	Key             string
	SessionID       string
	FlowKey         string
	ChunkStart      time.Time
	BucketMS        int
	ChunkMS         int
	Samples         []ActivityBucket
	WireBytesOut    int64
	WireBytesIn     int64
	PayloadBytesOut int64
	PayloadBytesIn  int64
	PacketsOut      int64
	PacketsIn       int64
	TCPFlagsOut     uint16
	TCPFlagsIn      uint16
	CaptureComplete bool
	DroppedEvents   int64
	UpdatedAtSource time.Time
	FirstObservedAt time.Time
	Generation      uint64
}

type activityChunkState struct {
	ActivityChunkSnapshot
	buckets map[int64]*ActivityBucket
	dirty   bool
}

type ActivityAggregator struct {
	bucketDuration time.Duration
	chunkDuration  time.Duration
	maxChunks      int
	chunks         map[string]*activityChunkState
}

func NewActivityAggregator(bucketDuration, chunkDuration time.Duration, maxChunks int) *ActivityAggregator {
	if bucketDuration <= 0 {
		bucketDuration = 50 * time.Millisecond
	}
	if chunkDuration < bucketDuration {
		chunkDuration = 5 * time.Second
	}
	if maxChunks <= 0 {
		maxChunks = 4096
	}
	return &ActivityAggregator{
		bucketDuration: bucketDuration,
		chunkDuration:  chunkDuration,
		maxChunks:      maxChunks,
		chunks:         make(map[string]*activityChunkState),
	}
}

func (aggregator *ActivityAggregator) Add(event PacketActivityEvent) bool {
	if event.SessionID == "" || event.FlowKey == "" || event.ObservedAt.IsZero() {
		return false
	}
	chunkStart := event.ObservedAt.UTC().Truncate(aggregator.chunkDuration)
	key := activityChunkKey(event.SessionID, event.FlowKey, chunkStart)
	state := aggregator.chunks[key]
	if state == nil {
		if len(aggregator.chunks) >= aggregator.maxChunks {
			return false
		}
		state = &activityChunkState{
			ActivityChunkSnapshot: ActivityChunkSnapshot{
				Key: key, SessionID: event.SessionID, FlowKey: event.FlowKey,
				ChunkStart: chunkStart, BucketMS: int(aggregator.bucketDuration / time.Millisecond),
				ChunkMS:         int(aggregator.chunkDuration / time.Millisecond),
				CaptureComplete: true, FirstObservedAt: event.ObservedAt, UpdatedAtSource: event.ObservedAt,
			},
			buckets: make(map[int64]*ActivityBucket),
		}
		aggregator.chunks[key] = state
	}

	bucketStart := event.ObservedAt.UTC().Truncate(aggregator.bucketDuration)
	offset := bucketStart.Sub(chunkStart).Milliseconds()
	bucket := state.buckets[offset]
	if bucket == nil {
		bucket = &ActivityBucket{OffsetMS: offset}
		state.buckets[offset] = bucket
	}
	wireBytes := int64(event.WireBytes)
	payloadBytes := int64(event.PayloadBytes)
	if event.Direction == RemoteToClient {
		bucket.PayloadBytesIn = saturatingAdd(bucket.PayloadBytesIn, payloadBytes)
		bucket.PacketsIn = saturatingAdd(bucket.PacketsIn, 1)
		state.WireBytesIn = saturatingAdd(state.WireBytesIn, wireBytes)
		state.PayloadBytesIn = saturatingAdd(state.PayloadBytesIn, payloadBytes)
		state.PacketsIn = saturatingAdd(state.PacketsIn, 1)
		state.TCPFlagsIn |= event.TCPFlags
	} else {
		bucket.PayloadBytesOut = saturatingAdd(bucket.PayloadBytesOut, payloadBytes)
		bucket.PacketsOut = saturatingAdd(bucket.PacketsOut, 1)
		state.WireBytesOut = saturatingAdd(state.WireBytesOut, wireBytes)
		state.PayloadBytesOut = saturatingAdd(state.PayloadBytesOut, payloadBytes)
		state.PacketsOut = saturatingAdd(state.PacketsOut, 1)
		state.TCPFlagsOut |= event.TCPFlags
	}
	if event.ObservedAt.After(state.UpdatedAtSource) {
		state.UpdatedAtSource = event.ObservedAt
	}
	state.Generation++
	state.dirty = true
	return true
}

func (aggregator *ActivityAggregator) MarkCaptureDrop(count int64, at time.Time) {
	if count <= 0 {
		return
	}
	for _, state := range aggregator.chunks {
		if !at.Before(state.ChunkStart) && at.Before(state.ChunkStart.Add(aggregator.chunkDuration)) {
			state.CaptureComplete = false
			state.DroppedEvents = saturatingAdd(state.DroppedEvents, count)
			state.Generation++
			state.dirty = true
		}
	}
}

func (aggregator *ActivityAggregator) DirtySnapshots() []ActivityChunkSnapshot {
	result := make([]ActivityChunkSnapshot, 0, len(aggregator.chunks))
	for _, state := range aggregator.chunks {
		if !state.dirty {
			continue
		}
		snapshot := state.ActivityChunkSnapshot
		snapshot.Samples = make([]ActivityBucket, 0, len(state.buckets))
		for _, bucket := range state.buckets {
			snapshot.Samples = append(snapshot.Samples, *bucket)
		}
		sort.Slice(snapshot.Samples, func(i, j int) bool { return snapshot.Samples[i].OffsetMS < snapshot.Samples[j].OffsetMS })
		result = append(result, snapshot)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ChunkStart.Before(result[j].ChunkStart) })
	return result
}

func (aggregator *ActivityAggregator) MarkPersisted(key string, generation uint64, now time.Time) {
	state := aggregator.chunks[key]
	if state == nil || state.Generation != generation {
		return
	}
	state.dirty = false
	if !now.Before(state.ChunkStart.Add(aggregator.chunkDuration + time.Second)) {
		delete(aggregator.chunks, key)
	}
}

func (aggregator *ActivityAggregator) Drop(key string) {
	delete(aggregator.chunks, key)
}

func (aggregator *ActivityAggregator) PrunePersisted(now time.Time) int {
	deleted := 0
	for key, state := range aggregator.chunks {
		if !state.dirty && !now.Before(state.ChunkStart.Add(aggregator.chunkDuration+time.Second)) {
			delete(aggregator.chunks, key)
			deleted++
		}
	}
	return deleted
}

func (aggregator *ActivityAggregator) Len() int {
	return len(aggregator.chunks)
}

func activityChunkKey(sessionID, flowKey string, start time.Time) string {
	return sessionID + "|" + flowKey + "|" + start.UTC().Format(time.RFC3339Nano)
}

func saturatingAdd(left, right int64) int64 {
	if right > 0 && left > math.MaxInt64-right {
		return math.MaxInt64
	}
	if right < 0 && left < math.MinInt64-right {
		return math.MinInt64
	}
	return left + right
}
