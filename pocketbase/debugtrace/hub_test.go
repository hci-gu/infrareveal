package debugtrace

import (
	"context"
	"errors"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestHubSequenceIsMonotonicUnderConcurrentEmission(t *testing.T) {
	hub := testHub(t, Config{RingEvents: 500, IngressBuffer: 500, MaxBatch: 50})
	var wait sync.WaitGroup
	for producer := 0; producer < 8; producer++ {
		wait.Add(1)
		go func(producer int) {
			defer wait.Done()
			for item := 0; item < 25; item++ {
				if !hub.TryEmit(validEvent("session", producer*25+item, time.Now())) {
					t.Errorf("unexpected ingress rejection")
				}
			}
		}(producer)
	}
	wait.Wait()
	waitForNewest(t, hub, 200)
	subscription, err := hub.Subscribe(context.Background(), "session", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	events := initialEvents(subscription.Initial)
	if len(events) != 200 {
		t.Fatalf("events = %d, want 200", len(events))
	}
	for index, event := range events {
		if event.Sequence != uint64(index+1) {
			t.Fatalf("sequence[%d] = %d", index, event.Sequence)
		}
	}
}

func TestHubRingEvictsByCountAndAgeAndReconnectReportsGap(t *testing.T) {
	var now atomic.Int64
	now.Store(time.Now().UnixMilli())
	hub := testHubWithClock(t, Config{RingEvents: 3, Retention: time.Second}, func() time.Time {
		return time.UnixMilli(now.Load())
	})
	for index := 0; index < 5; index++ {
		hub.TryEmit(validEvent("session", index, time.UnixMilli(now.Load())))
	}
	waitForNewest(t, hub, 5)
	subscription, err := hub.Subscribe(context.Background(), "session", 1)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	if len(subscription.Initial) < 3 || subscription.Initial[1].Type != "gap" || subscription.Initial[1].DroppedEvents != 1 {
		t.Fatalf("expected explicit reconnect gap, got %#v", subscription.Initial)
	}
	if got := len(initialEvents(subscription.Initial)); got != 3 {
		t.Fatalf("replayed events = %d, want 3", got)
	}

	now.Add(2_000)
	hub.TryEmit(validEvent("session", 6, time.UnixMilli(now.Load())))
	waitForNewest(t, hub, 6)
	stats, _ := hub.Stats(context.Background())
	if stats.RingEvents != 1 {
		t.Fatalf("age-retained events = %d, want 1", stats.RingEvents)
	}
}

func TestSlowSubscriberCannotBlockFastSubscriberOrIngress(t *testing.T) {
	hub := testHub(t, Config{RingEvents: 500, IngressBuffer: 500, SubscriberBuffer: 64, MaxBatch: 1, BatchInterval: time.Millisecond})
	slow, err := hub.Subscribe(context.Background(), "session", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	fast, err := hub.Subscribe(context.Background(), "session", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fast.Close()
	deadline := time.After(2 * time.Second)
	for index := 0; index < 200; index++ {
		if !hub.TryEmit(validEvent("session", index, time.Now())) {
			t.Fatal("unexpected ingress rejection")
		}
		// Drain the fast reader before the next event, regardless of scheduling.
		// The unread subscriber fills after 64 events and must never block it.
		select {
		case message := <-fast.Events:
			if len(message.Events) != 1 || message.Events[0].Sequence != uint64(index+1) {
				t.Fatalf("unexpected fast subscriber message: %#v", message)
			}
		case <-deadline:
			t.Fatalf("fast subscriber stalled after %d events", index)
		}
	}
	stats, _ := hub.Stats(context.Background())
	if stats.NewestSequence != 200 {
		t.Fatalf("ingress stalled at %d", stats.NewestSequence)
	}
}

func TestCanceledSubscribeDoesNotLeakSubscriber(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	returned := make(chan struct{})
	var once sync.Once
	hub := testHubWithClock(t, Config{MaxSubscribers: 1}, func() time.Time {
		once.Do(func() {
			// Cancel while the hub builds the initial response, and ensure the
			// caller has returned before the hub can hand off the subscription.
			cancel()
			<-returned
		})
		return time.Now()
	})
	_, err := hub.Subscribe(ctx, "session", 0)
	close(returned)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Subscribe error = %v, want context.Canceled", err)
	}
	stats, err := hub.Stats(context.Background())
	if err != nil || stats.Subscribers != 0 {
		t.Fatalf("canceled subscription retained: stats=%+v, err=%v", stats, err)
	}
}

func TestBurstCoalescingTotalsAndBoundaries(t *testing.T) {
	hub := testHub(t, Config{RingEvents: 20, IngressBuffer: 20})
	base := time.Now().Truncate(50 * time.Millisecond)
	for _, burst := range []BurstInput{
		{SessionID: "session", TraceID: "flow:one", FlowKey: "tcp|10.0.0.1|1000|1.1.1.1|443", Direction: ClientToRemote, OccurredAtMs: base.UnixMilli() + 1, WireBytes: 100, PayloadBytes: 80, PacketCount: 1, TCPFlags: 2},
		{SessionID: "session", TraceID: "flow:one", FlowKey: "tcp|10.0.0.1|1000|1.1.1.1|443", Direction: ClientToRemote, OccurredAtMs: base.UnixMilli() + 20, WireBytes: 120, PayloadBytes: 90, PacketCount: 2, TCPFlags: 16},
		{SessionID: "session", TraceID: "flow:one", FlowKey: "tcp|10.0.0.1|1000|1.1.1.1|443", Direction: ClientToRemote, OccurredAtMs: base.UnixMilli() + 51, WireBytes: 50, PayloadBytes: 30, PacketCount: 1},
	} {
		if !hub.TryBurst(burst) {
			t.Fatal("burst ingress rejected")
		}
	}
	waitForNewest(t, hub, 1)
	subscription, _ := hub.Subscribe(context.Background(), "session", 0)
	defer subscription.Close()
	events := initialEvents(subscription.Initial)
	if len(events) != 1 || events[0].Summary.WireBytes == nil || *events[0].Summary.WireBytes != 220 ||
		events[0].Summary.PacketCount == nil || *events[0].Summary.PacketCount != 3 ||
		events[0].Summary.TCPFlags == nil || *events[0].Summary.TCPFlags != 18 {
		t.Fatalf("unexpected coalesced burst: %#v", events)
	}
}

func TestSubscriberLimitAndSessionFiltering(t *testing.T) {
	hub := testHub(t, Config{RingEvents: 20, IngressBuffer: 20, MaxSubscribers: 1})
	hub.TryEmit(validEvent("session-a", 1, time.Now()))
	hub.TryEmit(validEvent("session-b", 2, time.Now()))
	waitForNewest(t, hub, 2)
	first, err := hub.Subscribe(context.Background(), "session-a", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer first.Close()
	for _, event := range initialEvents(first.Initial) {
		if event.SessionID != "session-a" {
			t.Fatalf("cross-session event leaked: %#v", event)
		}
	}
	if _, err := hub.Subscribe(context.Background(), "session-b", 0); !errors.Is(err, ErrMaxSubscribers) {
		t.Fatalf("second subscriber error = %v", err)
	}
}

func testHub(t *testing.T, config Config) *Hub {
	return testHubWithClock(t, config, time.Now)
}

func testHubWithClock(t *testing.T, config Config, clock func() time.Time) *Hub {
	t.Helper()
	config.Enabled = true
	if config.BatchInterval == 0 {
		config.BatchInterval = 2 * time.Millisecond
	}
	if config.Retention == 0 {
		config.Retention = time.Minute
	}
	hub := newHubWithClock(context.Background(), config, clock)
	t.Cleanup(hub.Close)
	return hub
}

func validEvent(session string, index int, occurred time.Time) Event {
	return Event{
		ID: "event-" + strconv.Itoa(index), SessionID: session, TraceID: "trace-" + strconv.Itoa(index),
		Kind: KindFlow, Stage: StageConntrack, OccurredAtMs: occurred.UnixMilli(), Timing: TimingObserved,
	}
}

func waitForNewest(t *testing.T, hub *Hub, newest uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := hub.Stats(context.Background())
		if err == nil && stats.NewestSequence >= newest {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("hub did not reach sequence %d", newest)
}

func initialEvents(messages []StreamMessage) []Event {
	var result []Event
	for _, message := range messages {
		result = append(result, message.Events...)
	}
	return result
}
