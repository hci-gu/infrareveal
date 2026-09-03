package observer

import (
	"context"
	"testing"
	"time"

	"myapp/debugtrace"
)

func TestLiveBurstTotalsMatchPersistedActivitySnapshot(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	hub := debugtrace.NewHub(ctx, debugtrace.Config{
		Enabled: true, RingEvents: 20, Retention: time.Minute, IngressBuffer: 20,
		SubscriberBuffer: 8, BatchInterval: time.Millisecond, MaxBatch: 20, MaxSubscribers: 2,
	})
	t.Cleanup(func() { cancel(); hub.Close() })
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	base := time.Now().UTC().Truncate(50 * time.Millisecond)
	events := []PacketActivityEvent{
		{ObservedAt: base.Add(time.Millisecond), SessionID: "session", FlowKey: "tcp|10.0.0.1|1000|1.1.1.1|443", Direction: ClientToRemote, Protocol: "tcp", WireBytes: 100, PayloadBytes: 80, TCPFlags: 2},
		{ObservedAt: base.Add(20 * time.Millisecond), SessionID: "session", FlowKey: "tcp|10.0.0.1|1000|1.1.1.1|443", Direction: ClientToRemote, Protocol: "tcp", WireBytes: 120, PayloadBytes: 90, TCPFlags: 16},
	}
	for _, event := range events {
		if !aggregator.Add(event) {
			t.Fatal("activity aggregator rejected fixture")
		}
		tracePacketActivity(hub, event)
	}
	tracePacketActivity(hub, PacketActivityEvent{
		ObservedAt: base.Add(51 * time.Millisecond), SessionID: "session", FlowKey: events[0].FlowKey,
		Direction: ClientToRemote, Protocol: "tcp", WireBytes: 1, PayloadBytes: 0,
	})

	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		stats, _ := hub.Stats(context.Background())
		if stats.NewestSequence >= 1 {
			break
		}
		time.Sleep(time.Millisecond)
	}
	subscription, err := hub.Subscribe(context.Background(), "session", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Close()
	var burst debugtrace.Event
	for _, message := range subscription.Initial {
		for _, event := range message.Events {
			if event.OccurredAtMs == base.UnixMilli() {
				burst = event
			}
		}
	}
	snapshots := aggregator.DirtySnapshots()
	if len(snapshots) != 1 || burst.Summary.WireBytes == nil || burst.Summary.PayloadBytes == nil || burst.Summary.PacketCount == nil || burst.Summary.TCPFlags == nil {
		t.Fatalf("missing snapshot or live burst: snapshots=%#v burst=%#v", snapshots, burst)
	}
	snapshot := snapshots[0]
	if *burst.Summary.WireBytes != uint64(snapshot.WireBytesOut) ||
		*burst.Summary.PayloadBytes != uint64(snapshot.PayloadBytesOut) ||
		*burst.Summary.PacketCount != uint64(snapshot.PacketsOut) ||
		*burst.Summary.TCPFlags != snapshot.TCPFlagsOut {
		t.Fatalf("live=%#v persisted=%#v", burst.Summary, snapshot)
	}
}
