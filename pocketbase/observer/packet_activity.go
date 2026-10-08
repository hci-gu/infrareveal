package observer

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"myapp/debugtrace"

	"github.com/pocketbase/pocketbase"
)

type PacketActivityConfig struct {
	Enabled              bool
	Interface            string
	BucketDuration       time.Duration
	ChunkDuration        time.Duration
	Retention            time.Duration
	FlushInterval        time.Duration
	PendingTTL           time.Duration
	MaxPendingChunks     int
	EventQueueSize       int
	PersistenceQueueSize int
}

func PacketActivityConfigFromEnv(defaultInterface string) PacketActivityConfig {
	if defaultInterface == "" {
		defaultInterface = "wlan0"
	}
	bucketMS := boundedEnvInt("PACKET_ACTIVITY_BUCKET_MS", 50, 20, 1000)
	chunkSeconds := boundedEnvInt("PACKET_ACTIVITY_CHUNK_SECONDS", 5, 1, 60)
	if time.Duration(chunkSeconds)*time.Second < time.Duration(bucketMS)*time.Millisecond {
		chunkSeconds = 5
	}
	return PacketActivityConfig{
		Enabled:              envBool("PACKET_ACTIVITY_ENABLED", true),
		Interface:            envString("PACKET_ACTIVITY_IFACE", defaultInterface),
		BucketDuration:       time.Duration(bucketMS) * time.Millisecond,
		ChunkDuration:        time.Duration(chunkSeconds) * time.Second,
		Retention:            time.Duration(boundedEnvInt("PACKET_ACTIVITY_RETENTION_HOURS", 24, 1, 24*365)) * time.Hour,
		FlushInterval:        400 * time.Millisecond,
		PendingTTL:           5 * time.Second,
		MaxPendingChunks:     boundedEnvInt("PACKET_ACTIVITY_MAX_PENDING_CHUNKS", 4096, 128, 65536),
		EventQueueSize:       boundedEnvInt("PACKET_ACTIVITY_EVENT_QUEUE", 8192, 256, 131072),
		PersistenceQueueSize: 256,
	}
}

type activityPersistRequest struct {
	snapshot       ActivityChunkSnapshot
	status         *ActivityCaptureStatus
	windowStart    time.Time
	windowDuration time.Duration
	windowDrops    int64
}

type activityPersistAck struct {
	key        string
	generation uint64
	result     activityPersistResult
	err        error
}

type captureStateEvent struct {
	running bool
	err     error
}

type packetSource func(context.Context, string, ObservationScope, func(), func(PacketActivityEvent)) error

// Only the aggregation owner touches chunks/generations. One private writer owns
// every blocking save, including health windows. Bounded queues preserve capture
// backpressure and Close drains accepted events before joining the writer.
type packetPipeline struct {
	config              PacketActivityConfig
	sessionID           func() string
	trace               debugtrace.Sink
	events              chan PacketActivityEvent
	requests            chan activityPersistRequest
	acks                chan activityPersistAck
	states              chan captureStateEvent
	dropped             atomic.Int64
	stopCapture         context.CancelFunc
	aggregateDone, done chan struct{}
	err                 error
	closeOnce           sync.Once
}

func startPacketPipeline(app *pocketbase.PocketBase, scope ObservationScope, sessionID func() string, config PacketActivityConfig, trace debugtrace.Sink, source packetSource) *packetPipeline {
	if config.EventQueueSize <= 0 {
		config.EventQueueSize = 8192
	}
	if config.PersistenceQueueSize <= 0 {
		config.PersistenceQueueSize = 256
	}
	if config.FlushInterval <= 0 {
		config.FlushInterval = 400 * time.Millisecond
	}
	if config.BucketDuration <= 0 {
		config.BucketDuration = 50 * time.Millisecond
	}
	if config.ChunkDuration <= 0 {
		config.ChunkDuration = 5 * time.Second
	}
	if config.PendingTTL <= 0 {
		config.PendingTTL = 5 * time.Second
	}
	ctx, cancel := context.WithCancel(context.Background())
	p := &packetPipeline{config: config, sessionID: sessionID, trace: usableTraceSink(trace), events: make(chan PacketActivityEvent, config.EventQueueSize), requests: make(chan activityPersistRequest, config.PersistenceQueueSize), acks: make(chan activityPersistAck, config.PersistenceQueueSize), states: make(chan captureStateEvent, 8), stopCapture: cancel, aggregateDone: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.events)
		if !config.Enabled || source == nil {
			<-ctx.Done()
			return
		}
		for {
			err := source(ctx, config.Interface, scope, func() {
				select {
				case p.states <- captureStateEvent{running: true}:
				default:
				}
			}, func(event PacketActivityEvent) {
				event.SessionID = sessionID()
				if event.SessionID != "" {
					enqueuePacketActivity(p.events, event, &p.dropped)
				}
			})
			if ctx.Err() != nil {
				return
			}
			select {
			case p.states <- captureStateEvent{err: err}:
			default:
			}
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
		}
	}()
	go func() { p.err = p.aggregate(); close(p.aggregateDone); close(p.requests) }()
	go func() {
		defer close(p.done)
		var healthErr error
		for request := range p.requests {
			var err error
			if request.status != nil {
				err = upsertActivityCaptureStatus(app, *request.status)
				if err == nil {
					err = upsertActivityCaptureWindow(app, request.status.SessionID, request.windowStart, request.windowDuration, request.status.Running, request.windowDrops, request.status.LastError)
				}
				if err != nil && healthErr == nil {
					healthErr = err
				}
				if err != nil {
					log.Printf("packet activity health persistence: %v", err)
				}
			} else {
				result, err := persistActivityChunk(app, request.snapshot)
				ack := activityPersistAck{key: request.snapshot.Key, generation: request.snapshot.Generation, result: result, err: err}
				select {
				case p.acks <- ack:
				case <-p.aggregateDone:
				}
			}
		}
		p.err = errors.Join(p.err, healthErr)
	}()
	return p
}
func (p *packetPipeline) Close(ctx context.Context) error {
	p.closeOnce.Do(p.stopCapture)
	select {
	case <-p.done:
		return p.err
	case <-ctx.Done():
		return fmt.Errorf("packet activity drain: %w", ctx.Err())
	}
}

func (p *packetPipeline) aggregate() error {
	config, sessionID, trace := p.config, p.sessionID, p.trace
	events, persistRequests, persistAcks, captureState, droppedEvents := p.events, p.requests, p.acks, p.states, &p.dropped
	aggregator := NewActivityAggregator(config.BucketDuration, config.ChunkDuration, config.MaxPendingChunks)
	flushTicker := time.NewTicker(config.FlushInterval)
	statusTicker := time.NewTicker(2 * time.Second)
	defer flushTicker.Stop()
	defer statusTicker.Stop()

	inFlight := make(map[string]uint64)
	lastDropped := int64(0)
	// Matching failures have a known flow key and are not capture-queue loss.
	// Keep them out of the counter that marks every active chunk incomplete.
	var unmatchedEvents int64
	lastEventAt := time.Time{}
	running := false
	lastError := ""
	windowSessionID := ""
	windowDrops := make(map[time.Time]int64)
	emitHealth := func(now time.Time, complete bool, dropped int64) {
		activeSessionID := sessionID()
		if activeSessionID == "" {
			return
		}
		captureComplete := complete
		trace.TryEmit(debugtrace.Event{
			ID: traceEventID("capture-health", config.Interface, now), SessionID: activeSessionID,
			TraceID: "capture:" + config.Interface, Kind: debugtrace.KindHealth, Stage: debugtrace.StageHealth,
			OccurredAtMs: now.UnixMilli(), ProcessedAtMs: traceProcessedNow(), Timing: debugtrace.TimingObserved,
			Summary: debugtrace.Summary{DroppedEvents: traceCount(dropped), CaptureComplete: &captureComplete},
		})
	}
	defer func() { emitHealth(time.Now().UTC(), false, droppedEvents.Load()) }()

	statusRequest := func(now time.Time) activityPersistRequest {
		activeSessionID := sessionID()
		currentWindowStart := now.UTC().Truncate(config.ChunkDuration)
		if activeSessionID != windowSessionID {
			windowSessionID = activeSessionID
			windowDrops = make(map[time.Time]int64)
		}
		for start := range windowDrops {
			if start.Before(currentWindowStart.Add(-config.ChunkDuration)) {
				delete(windowDrops, start)
			}
		}
		request := activityPersistRequest{status: &ActivityCaptureStatus{
			SessionID: activeSessionID, Interface: config.Interface, Enabled: config.Enabled, Running: running,
			DroppedEvents: droppedEvents.Load(), LastError: lastError, UnmatchedEvents: unmatchedEvents, LastEventAt: lastEventAt,
		}, windowStart: currentWindowStart, windowDuration: config.ChunkDuration, windowDrops: windowDrops[currentWindowStart]}
		return request
	}
	reportStatus := func(now time.Time) {
		select {
		case persistRequests <- statusRequest(now):
		default:
		}
	}

	accountDrops := func(now time.Time) {
		currentDropped := droppedEvents.Load()
		if delta := currentDropped - lastDropped; delta > 0 {
			aggregator.MarkCaptureDrop(delta, now)
			windowDrops[now.UTC().Truncate(config.ChunkDuration)] += delta
			log.Printf("packet activity dropped %d metadata events under backpressure (total %d)", delta, currentDropped)
			emitHealth(now.UTC(), false, currentDropped)
			lastDropped = currentDropped
		}
	}
	var draining bool
	var deadline <-chan time.Time
	for {
		if draining {
			accountDrops(time.Now())
		}
		if draining && len(inFlight) == 0 && aggregator.dirtyCount() == 0 {
			running = false
			select {
			case persistRequests <- statusRequest(time.Now()):
				return nil
			case <-deadline:
				return fmt.Errorf("packet activity final health persistence queue did not drain")
			}
		}
		select {
		case <-deadline:
			return fmt.Errorf("packet activity final drain left %d dirty chunks (%s)", aggregator.dirtyCount(), lastError)
		case state := <-captureState:
			running = state.running
			if state.err != nil {
				lastError = state.err.Error()
				log.Printf("packet activity capture unavailable on %s: %v; connection timelines remain available", config.Interface, state.err)
			} else if state.running {
				lastError = ""
				log.Printf("packet activity capture enabled on %s with %s buckets", config.Interface, config.BucketDuration)
			}
			reportStatus(time.Now())
			emitHealth(time.Now().UTC(), state.running && state.err == nil, droppedEvents.Load())
		case event, ok := <-events:
			if !ok {
				events = nil
				draining = true
				deadline = time.After(min(8*time.Second, max(3*time.Second, config.PendingTTL+config.FlushInterval)))
				continue
			}
			lastEventAt = event.ObservedAt
			tracePacketActivity(trace, event)
			if !aggregator.Add(event) {
				droppedEvents.Add(1)
			}
		case ack := <-persistAcks:
			delete(inFlight, ack.key)
			if ack.err != nil {
				lastError = "activity persistence: " + ack.err.Error()
				log.Printf("packet activity persistence error: %v", ack.err)
				continue
			}
			if strings.HasPrefix(lastError, "activity persistence:") {
				lastError = ""
			}
			if ack.result == activityFlowPending {
				if expirePendingActivityCount(aggregator, ack.key, config.PendingTTL, time.Now(), &unmatchedEvents) {
					log.Printf("packet activity expired unmatched chunk %s after %s without an in-scope conntrack flow (unmatched observations total %d)", ack.key, config.PendingTTL, unmatchedEvents)
				}
				continue
			}
			aggregator.MarkPersisted(ack.key, ack.generation, time.Now())
		case now := <-flushTicker.C:
			aggregator.PrunePersisted(now)
			accountDrops(now)
			queueFull := false
			for _, snapshot := range aggregator.DirtySnapshots() {
				if _, busy := inFlight[snapshot.Key]; busy {
					continue
				}
				select {
				case persistRequests <- activityPersistRequest{snapshot: snapshot}:
					inFlight[snapshot.Key] = snapshot.Generation
				default:
					lastError = "activity persistence queue is full"
					queueFull = true
				}
			}
			if !queueFull && lastError == "activity persistence queue is full" {
				lastError = ""
			}
		case now := <-statusTicker.C:
			reportStatus(now)
		}
	}
}

func tracePacketActivity(trace debugtrace.Sink, event PacketActivityEvent) {
	trace.TryBurst(debugtrace.BurstInput{
		SessionID: event.SessionID, TraceID: "flow:" + event.FlowKey, FlowKey: event.FlowKey,
		Protocol: event.Protocol, Direction: debugtrace.Direction(event.Direction), OccurredAtMs: event.ObservedAt.UnixMilli(),
		WireBytes: uint64(event.WireBytes), PayloadBytes: uint64(event.PayloadBytes), PacketCount: 1, TCPFlags: event.TCPFlags,
	})
}

func enqueuePacketActivity(events chan<- PacketActivityEvent, event PacketActivityEvent, dropped *atomic.Int64) bool {
	select {
	case events <- event:
		return true
	default:
		dropped.Add(1)
		return false
	}
}

func expirePendingActivityCount(aggregator *ActivityAggregator, key string, ttl time.Duration, now time.Time, unmatched *int64) bool {
	count, expired := aggregator.ExpirePending(key, ttl, now)
	*unmatched += count
	return expired
}

func envBool(name string, fallback bool) bool {
	value := strings.TrimSpace(strings.ToLower(os.Getenv(name)))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func boundedEnvInt(name string, fallback, minimum, maximum int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func envString(name, fallback string) string {
	if value := strings.TrimSpace(os.Getenv(name)); value != "" {
		return value
	}
	return fallback
}

var errPacketCaptureUnsupported = errors.New("packet activity capture is only supported on Linux")
