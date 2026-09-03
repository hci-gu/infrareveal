package debugtrace

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"
)

var (
	ErrHubClosed      = errors.New("debug trace hub is closed")
	ErrMaxSubscribers = errors.New("debug trace subscriber limit reached")
)

type StreamMessage struct {
	Type              string  `json:"type"`
	Version           uint8   `json:"version"`
	SessionID         string  `json:"sessionId"`
	Events            []Event `json:"events,omitempty"`
	DroppedEvents     uint64  `json:"droppedEvents"`
	ServerNowMs       int64   `json:"serverNowMs"`
	RequestedSequence uint64  `json:"requestedSequence,omitempty"`
	OldestSequence    uint64  `json:"oldestSequence"`
	NewestSequence    uint64  `json:"newestSequence"`
	IngressRejected   uint64  `json:"ingressRejected,omitempty"`
	SubscriberDropped uint64  `json:"subscriberDropped,omitempty"`
	BurstDiscarded    uint64  `json:"burstDiscarded,omitempty"`
}

type HubStats struct {
	OldestSequence  uint64
	NewestSequence  uint64
	RingEvents      int
	Subscribers     int
	IngressRejected uint64
	InvalidEvents   uint64
	BurstDiscarded  uint64
}

type Subscription struct {
	Initial []StreamMessage
	Events  <-chan StreamMessage
	cancel  func()
	once    sync.Once
}

func (subscription *Subscription) Close() {
	subscription.once.Do(subscription.cancel)
}

type subscriber struct {
	id        uint64
	sessionID string
	events    chan StreamMessage
	liveAfter uint64
	dropped   uint64
}

type subscribeRequest struct {
	sessionID string
	after     uint64
	reply     chan subscribeResponse
}

type subscribeResponse struct {
	subscription *Subscription
	err          error
}

type removeSubscriber uint64

type snapshotRequest struct {
	reply chan HubStats
}

type Hub struct {
	config         Config
	ingress        *Ingress
	commands       chan any
	ctx            context.Context
	cancel         context.CancelFunc
	done           chan struct{}
	closed         atomic.Bool
	invalidEvents  atomic.Uint64
	burstDiscarded atomic.Uint64
	now            func() time.Time
}

func NewHub(parent context.Context, config Config) *Hub {
	return newHubWithClock(parent, config, time.Now)
}

// NewRuntime keeps disabled tracing completely inert: no hub, channel, or
// goroutine is allocated, and callers receive a shareable no-op sink.
func NewRuntime(parent context.Context, config Config) (*Hub, Sink) {
	if !config.Enabled {
		return nil, NopSink{}
	}
	hub := NewHub(parent, config)
	return hub, hub
}

func newHubWithClock(parent context.Context, config Config, now func() time.Time) *Hub {
	config = config.withDefaults()
	ctx, cancel := context.WithCancel(parent)
	hub := &Hub{
		config: config, ingress: NewIngress(config.IngressBuffer), commands: make(chan any, 64),
		ctx: ctx, cancel: cancel, done: make(chan struct{}), now: now,
	}
	go hub.run()
	return hub
}

func (hub *Hub) TryEmit(event Event) bool {
	if hub == nil || hub.closed.Load() {
		return false
	}
	return hub.ingress.TryEmit(event)
}

func (hub *Hub) TryBurst(burst BurstInput) bool {
	if hub == nil || hub.closed.Load() {
		return false
	}
	return hub.ingress.TryBurst(burst)
}

func (hub *Hub) Subscribe(ctx context.Context, sessionID string, afterSequence uint64) (*Subscription, error) {
	if hub == nil || hub.closed.Load() {
		return nil, ErrHubClosed
	}
	reply := make(chan subscribeResponse, 1)
	request := subscribeRequest{sessionID: sessionID, after: afterSequence, reply: reply}
	select {
	case hub.commands <- request:
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-hub.done:
		return nil, ErrHubClosed
	}
	select {
	case result := <-reply:
		return result.subscription, result.err
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-hub.done:
		return nil, ErrHubClosed
	}
}

func (hub *Hub) Stats(ctx context.Context) (HubStats, error) {
	if hub == nil || hub.closed.Load() {
		return HubStats{}, ErrHubClosed
	}
	reply := make(chan HubStats, 1)
	select {
	case hub.commands <- snapshotRequest{reply: reply}:
	case <-ctx.Done():
		return HubStats{}, ctx.Err()
	case <-hub.done:
		return HubStats{}, ErrHubClosed
	}
	select {
	case stats := <-reply:
		return stats, nil
	case <-ctx.Done():
		return HubStats{}, ctx.Err()
	case <-hub.done:
		return HubStats{}, ErrHubClosed
	}
}

func (hub *Hub) Close() {
	if hub == nil || hub.closed.Swap(true) {
		return
	}
	hub.cancel()
	<-hub.done
}

func (hub *Hub) run() {
	defer close(hub.done)
	ticker := time.NewTicker(hub.config.BatchInterval)
	defer ticker.Stop()
	ring := make([]Event, 0, hub.config.RingEvents)
	subscribers := make(map[uint64]*subscriber)
	coalescer := newBurstCoalescer(hub.config.IngressBuffer)
	var sequence uint64
	var subscriberID uint64
	batch := make([]Event, 0, hub.config.MaxBatch)

	oldest := func() uint64 {
		if len(ring) == 0 {
			return sequence + 1
		}
		return ring[0].Sequence
	}
	prune := func(now time.Time) {
		cutoff := now.Add(-hub.config.Retention).UnixMilli()
		remove := 0
		for remove < len(ring) && (len(ring)-remove > hub.config.RingEvents || ring[remove].OccurredAtMs < cutoff) {
			remove++
		}
		if remove > 0 {
			copy(ring, ring[remove:])
			ring = ring[:len(ring)-remove]
		}
	}
	flushBatch := func() {
		if len(batch) == 0 {
			return
		}
		for _, current := range subscribers {
			filtered := make([]Event, 0, len(batch))
			latest := current.liveAfter
			for _, event := range batch {
				if event.Sequence > current.liveAfter && event.SessionID == current.sessionID {
					filtered = append(filtered, event)
					latest = max(latest, event.Sequence)
				}
			}
			if len(filtered) == 0 {
				continue
			}
			if current.dropped > 0 {
				status := hub.message("status", current.sessionID, sequence, oldest())
				status.SubscriberDropped = current.dropped
				select {
				case current.events <- status:
					current.dropped = 0
				default:
				}
			}
			message := hub.message("batch", current.sessionID, sequence, oldest())
			message.Events = filtered
			select {
			case current.events <- message:
			default:
				current.dropped += uint64(len(filtered))
			}
			current.liveAfter = latest
		}
		batch = batch[:0]
	}
	accept := func(event Event) {
		if event.ProcessedAtMs == nil {
			processed := hub.now().UnixMilli()
			event.ProcessedAtMs = &processed
		}
		if err := event.Validate(); err != nil {
			hub.invalidEvents.Add(1)
			return
		}
		sequence++
		event.Sequence = sequence
		ring = append(ring, event)
		prune(hub.now())
		batch = append(batch, event)
		if len(batch) >= hub.config.MaxBatch {
			flushBatch()
		}
	}

	for {
		select {
		case <-hub.ctx.Done():
			for _, event := range coalescer.flushBefore(int64(^uint64(0) >> 1)) {
				accept(event)
			}
			flushBatch()
			for _, current := range subscribers {
				close(current.events)
			}
			return
		case item := <-hub.ingress.items:
			if item.kind == ingressEvent {
				accept(item.event)
				continue
			}
			flushed, accepted := coalescer.add(item.burst)
			if !accepted {
				hub.burstDiscarded.Add(1)
			}
			for _, event := range flushed {
				accept(event)
			}
		case now := <-ticker.C:
			for _, event := range coalescer.flushBefore(now.Add(-burstBucketDuration).UnixMilli()) {
				accept(event)
			}
			prune(now)
			flushBatch()
		case command := <-hub.commands:
			switch request := command.(type) {
			case subscribeRequest:
				if len(subscribers) >= hub.config.MaxSubscribers {
					request.reply <- subscribeResponse{err: ErrMaxSubscribers}
					continue
				}
				subscriberID++
				current := &subscriber{
					id: subscriberID, sessionID: request.sessionID,
					events:    make(chan StreamMessage, hub.config.SubscriberBuffer),
					liveAfter: min(request.after, sequence),
				}
				initial := []StreamMessage{hub.message("hello", request.sessionID, sequence, oldest())}
				if request.after > 0 && request.after+1 < oldest() {
					gap := hub.message("gap", request.sessionID, sequence, oldest())
					gap.RequestedSequence = request.after
					gap.DroppedEvents = oldest() - request.after - 1
					initial = append(initial, gap)
				}
				replay := make([]Event, 0)
				for _, event := range ring {
					if event.Sequence > request.after && event.SessionID == request.sessionID {
						replay = append(replay, event)
					}
				}
				for start := 0; start < len(replay); start += hub.config.MaxBatch {
					end := min(start+hub.config.MaxBatch, len(replay))
					message := hub.message("batch", request.sessionID, sequence, oldest())
					message.Events = replay[start:end]
					initial = append(initial, message)
				}
				current.liveAfter = sequence
				subscription := &Subscription{Initial: initial, Events: current.events}
				subscription.cancel = func() {
					select {
					case hub.commands <- removeSubscriber(current.id):
					case <-hub.done:
					}
				}
				subscribers[current.id] = current
				request.reply <- subscribeResponse{subscription: subscription}
			case removeSubscriber:
				if current := subscribers[uint64(request)]; current != nil {
					delete(subscribers, current.id)
					close(current.events)
				}
			case snapshotRequest:
				request.reply <- HubStats{
					OldestSequence: oldest(), NewestSequence: sequence, RingEvents: len(ring), Subscribers: len(subscribers),
					IngressRejected: hub.ingress.Rejected(), InvalidEvents: hub.invalidEvents.Load(), BurstDiscarded: hub.burstDiscarded.Load(),
				}
			}
		}
	}
}

func (hub *Hub) message(kind, sessionID string, newest, oldest uint64) StreamMessage {
	return StreamMessage{
		Type: kind, Version: ProtocolVersion, SessionID: sessionID, ServerNowMs: hub.now().UnixMilli(),
		OldestSequence: oldest, NewestSequence: newest, IngressRejected: hub.ingress.Rejected(),
		BurstDiscarded: hub.burstDiscarded.Load(),
	}
}
