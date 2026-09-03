package observer

import (
	"context"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
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
	snapshot ActivityChunkSnapshot
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

func StartPacketActivityObserver(
	ctx context.Context,
	app *pocketbase.PocketBase,
	scope ObservationScope,
	sessionID func() string,
	config PacketActivityConfig,
	trace debugtrace.Sink,
) {
	trace = usableTraceSink(trace)
	events := make(chan PacketActivityEvent, config.EventQueueSize)
	persistRequests := make(chan activityPersistRequest, config.PersistenceQueueSize)
	persistAcks := make(chan activityPersistAck, config.PersistenceQueueSize)
	captureState := make(chan captureStateEvent, 8)
	var droppedEvents atomic.Int64

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case request := <-persistRequests:
				result, err := persistActivityChunk(app, request.snapshot)
				ack := activityPersistAck{
					key: request.snapshot.Key, generation: request.snapshot.Generation,
					result: result, err: err,
				}
				select {
				case persistAcks <- ack:
				case <-ctx.Done():
					return
				}
			}
		}
	}()

	if config.Enabled {
		go func() {
			for {
				err := runPacketCapture(ctx, config.Interface, scope, func() {
					select {
					case captureState <- captureStateEvent{running: true}:
					default:
					}
				}, func(event PacketActivityEvent) {
					event.SessionID = sessionID()
					if event.SessionID == "" {
						return
					}
					enqueuePacketActivity(events, event, &droppedEvents)
				})
				if ctx.Err() != nil {
					return
				}
				select {
				case captureState <- captureStateEvent{running: false, err: err}:
				default:
				}
				select {
				case <-ctx.Done():
					return
				case <-time.After(5 * time.Second):
				}
			}
		}()
	}

	go runPacketActivityPipeline(ctx, app, sessionID, config, events, persistRequests, persistAcks, captureState, &droppedEvents, trace)
}

func runPacketActivityPipeline(
	ctx context.Context,
	app *pocketbase.PocketBase,
	sessionID func() string,
	config PacketActivityConfig,
	events <-chan PacketActivityEvent,
	persistRequests chan<- activityPersistRequest,
	persistAcks <-chan activityPersistAck,
	captureState <-chan captureStateEvent,
	droppedEvents *atomic.Int64,
	trace debugtrace.Sink,
) {
	aggregator := NewActivityAggregator(config.BucketDuration, config.ChunkDuration, config.MaxPendingChunks)
	flushTicker := time.NewTicker(config.FlushInterval)
	statusTicker := time.NewTicker(2 * time.Second)
	retentionTicker := time.NewTicker(time.Minute)
	defer flushTicker.Stop()
	defer statusTicker.Stop()
	defer retentionTicker.Stop()

	inFlight := make(map[string]uint64)
	lastDropped := int64(0)
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
	defer emitHealth(time.Now().UTC(), false, droppedEvents.Load())

	reportStatus := func(now time.Time) {
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
		if err := upsertActivityCaptureStatus(app, ActivityCaptureStatus{
			SessionID: activeSessionID, Interface: config.Interface, Enabled: config.Enabled,
			Running: running, DroppedEvents: droppedEvents.Load(), LastError: lastError,
			LastEventAt: lastEventAt,
		}); err != nil {
			log.Printf("packet activity status error: %v", err)
		}
		if err := upsertActivityCaptureWindow(
			app,
			activeSessionID,
			currentWindowStart,
			config.ChunkDuration,
			running,
			windowDrops[currentWindowStart],
			lastError,
		); err != nil {
			log.Printf("packet activity window error: %v", err)
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
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
		case event := <-events:
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
				if expirePendingActivity(aggregator, ack.key, config.PendingTTL, time.Now(), droppedEvents) {
					log.Printf("packet activity dropped unresolved chunk %s after %s without an in-scope conntrack flow", ack.key, config.PendingTTL)
				}
				continue
			}
			aggregator.MarkPersisted(ack.key, ack.generation, time.Now())
		case now := <-flushTicker.C:
			aggregator.PrunePersisted(now)
			currentDropped := droppedEvents.Load()
			if delta := currentDropped - lastDropped; delta > 0 {
				aggregator.MarkCaptureDrop(delta, now)
				windowDrops[now.UTC().Truncate(config.ChunkDuration)] += delta
				log.Printf("packet activity dropped %d metadata events under backpressure (total %d)", delta, currentDropped)
				emitHealth(now.UTC(), false, currentDropped)
				lastDropped = currentDropped
			}
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
		case <-retentionTicker.C:
			deleted, err := pruneExpiredActivityChunks(app, time.Now().Add(-config.Retention), 500)
			if err != nil {
				log.Printf("packet activity retention error: %v", err)
			} else if deleted > 0 {
				log.Printf("packet activity retention removed %d expired chunks", deleted)
			}
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

func expirePendingActivity(aggregator *ActivityAggregator, key string, ttl time.Duration, now time.Time, dropped *atomic.Int64) bool {
	for _, snapshot := range aggregator.DirtySnapshots() {
		if snapshot.Key == key && now.Sub(snapshot.FirstObservedAt) > ttl {
			dropped.Add(snapshot.PacketsIn + snapshot.PacketsOut)
			aggregator.Drop(snapshot.Key)
			return true
		}
	}
	return false
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
