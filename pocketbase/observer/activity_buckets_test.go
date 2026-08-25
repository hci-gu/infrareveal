package observer

import (
	"math"
	"testing"
	"time"
)

func TestActivityAggregatorBuildsSparseDirectionalBuckets(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	events := []PacketActivityEvent{
		activityEvent(start, ClientToRemote, 420, 100),
		activityEvent(start.Add(60*time.Millisecond), RemoteToClient, 1000, 900),
		activityEvent(start.Add(110*time.Millisecond), RemoteToClient, 2000, 1900),
	}
	for _, event := range events {
		if !aggregator.Add(event) {
			t.Fatal("expected event to be accepted")
		}
	}

	snapshots := aggregator.DirtySnapshots()
	if len(snapshots) != 1 {
		t.Fatalf("expected one chunk, got %d", len(snapshots))
	}
	snapshot := snapshots[0]
	if len(snapshot.Samples) != 3 {
		t.Fatalf("expected a 120ms transfer to occupy three 50ms buckets, got %#v", snapshot.Samples)
	}
	if snapshot.Samples[0].OffsetMS != 0 || snapshot.Samples[0].PayloadBytesOut != 100 {
		t.Fatalf("unexpected outbound sample: %#v", snapshot.Samples[0])
	}
	if snapshot.Samples[1].OffsetMS != 50 || snapshot.Samples[2].OffsetMS != 100 {
		t.Fatalf("unexpected inbound sample offsets: %#v", snapshot.Samples)
	}
	if snapshot.PayloadBytesOut != 100 || snapshot.PayloadBytesIn != 2800 || snapshot.PacketsIn != 2 {
		t.Fatalf("unexpected chunk totals: %#v", snapshot)
	}
}

func TestActivityAggregatorKeepsSeparatedBurstsSparse(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	aggregator.Add(activityEvent(start, ClientToRemote, 100, 60))
	aggregator.Add(activityEvent(start.Add(300*time.Millisecond), RemoteToClient, 500, 460))

	samples := aggregator.DirtySnapshots()[0].Samples
	if len(samples) != 2 || samples[0].OffsetMS != 0 || samples[1].OffsetMS != 300 {
		t.Fatalf("expected separate sparse burst buckets, got %#v", samples)
	}
}

func TestActivityAggregatorGenerationPreventsLostUpdates(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	aggregator.Add(activityEvent(start, ClientToRemote, 100, 60))
	first := aggregator.DirtySnapshots()[0]
	aggregator.Add(activityEvent(start.Add(20*time.Millisecond), ClientToRemote, 100, 60))
	aggregator.MarkPersisted(first.Key, first.Generation, start.Add(6*time.Second))
	if len(aggregator.DirtySnapshots()) != 1 {
		t.Fatal("expected a newer generation to remain dirty")
	}
	latest := aggregator.DirtySnapshots()[0]
	aggregator.MarkPersisted(latest.Key, latest.Generation, start.Add(6*time.Second))
	if aggregator.Len() != 0 {
		t.Fatal("expected completed persisted chunk to leave memory")
	}
}

func TestActivityAggregatorPrunesCleanCompletedChunks(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	aggregator.Add(activityEvent(start, ClientToRemote, 100, 60))
	snapshot := aggregator.DirtySnapshots()[0]
	aggregator.MarkPersisted(snapshot.Key, snapshot.Generation, start.Add(time.Second))
	if aggregator.PrunePersisted(start.Add(5*time.Second)) != 0 {
		t.Fatal("clean chunk was pruned before the late-packet grace period")
	}
	if aggregator.PrunePersisted(start.Add(6*time.Second)) != 1 || aggregator.Len() != 0 {
		t.Fatal("expected completed clean chunk to be removed from bounded memory")
	}
}

func TestActivityAggregatorMarksCaptureDrops(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	aggregator.Add(activityEvent(start, ClientToRemote, 100, 60))
	aggregator.MarkCaptureDrop(3, start.Add(time.Second))
	snapshot := aggregator.DirtySnapshots()[0]
	if snapshot.CaptureComplete || snapshot.DroppedEvents != 3 {
		t.Fatalf("expected incomplete capture metadata, got %#v", snapshot)
	}
}

func TestActivityAggregatorBoundsPendingChunks(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, time.Second, 1)
	if !aggregator.Add(activityEvent(start, ClientToRemote, 100, 60)) {
		t.Fatal("expected first chunk to fit")
	}
	if aggregator.Add(activityEvent(start.Add(2*time.Second), ClientToRemote, 100, 60)) {
		t.Fatal("expected second chunk to be rejected at the configured bound")
	}
}

func TestSaturatingAddProtectsCounters(t *testing.T) {
	if got := saturatingAdd(math.MaxInt64-1, 10); got != math.MaxInt64 {
		t.Fatalf("expected positive saturation, got %d", got)
	}
	if got := saturatingAdd(math.MinInt64+1, -10); got != math.MinInt64 {
		t.Fatalf("expected negative saturation, got %d", got)
	}
}

func activityEvent(at time.Time, direction Direction, wireBytes, payloadBytes uint32) PacketActivityEvent {
	return PacketActivityEvent{
		ObservedAt: at, SessionID: "session", FlowKey: "tcp|10.0.0.50|53000|93.184.216.34|443",
		Direction: direction, Protocol: "tcp", WireBytes: wireBytes, PayloadBytes: payloadBytes, TCPFlags: 0x18,
	}
}

func BenchmarkActivityAggregatorReplay(b *testing.B) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	for index := 0; index < b.N; index++ {
		aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 4096)
		for packet := 0; packet < 10_000; packet++ {
			event := activityEvent(start.Add(time.Duration(packet)*time.Millisecond), Direction(packet%2+1), 1500, 1440)
			aggregator.Add(event)
		}
		_ = aggregator.DirtySnapshots()
	}
}
