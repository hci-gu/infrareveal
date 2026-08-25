package observer

import (
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketActivityBackpressureIsNonBlockingAndCounted(t *testing.T) {
	events := make(chan PacketActivityEvent, 1)
	var dropped atomic.Int64
	event := activityEvent(time.Now(), ClientToRemote, 100, 60)
	if !enqueuePacketActivity(events, event, &dropped) {
		t.Fatal("expected first event to fit")
	}
	started := time.Now()
	if enqueuePacketActivity(events, event, &dropped) {
		t.Fatal("expected full queue to drop the second event")
	}
	if time.Since(started) > 50*time.Millisecond {
		t.Fatal("full activity queue blocked the producer")
	}
	if dropped.Load() != 1 {
		t.Fatalf("expected one accounted drop, got %d", dropped.Load())
	}
}

func TestPendingActivityExpiresAfterTTL(t *testing.T) {
	start := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)
	aggregator := NewActivityAggregator(50*time.Millisecond, 5*time.Second, 10)
	aggregator.Add(activityEvent(start, ClientToRemote, 100, 60))
	snapshot := aggregator.DirtySnapshots()[0]
	var dropped atomic.Int64
	if expirePendingActivity(aggregator, snapshot.Key, 5*time.Second, start.Add(5*time.Second), &dropped) {
		t.Fatal("pending activity expired at rather than after the TTL")
	}
	if !expirePendingActivity(aggregator, snapshot.Key, 5*time.Second, start.Add(5*time.Second+time.Nanosecond), &dropped) {
		t.Fatal("expected unresolved activity to expire")
	}
	if aggregator.Len() != 0 || dropped.Load() != 1 {
		t.Fatalf("expected one packet to be dropped and state removed: len=%d dropped=%d", aggregator.Len(), dropped.Load())
	}
}

func TestPacketActivityConfigValidatesEnvironment(t *testing.T) {
	t.Setenv("PACKET_ACTIVITY_BUCKET_MS", "5")
	t.Setenv("PACKET_ACTIVITY_CHUNK_SECONDS", "120")
	t.Setenv("PACKET_ACTIVITY_RETENTION_HOURS", "0")
	t.Setenv("PACKET_ACTIVITY_IFACE", "ap-test0")
	config := PacketActivityConfigFromEnv("wlan0")
	if config.BucketDuration != 50*time.Millisecond || config.ChunkDuration != 5*time.Second || config.Retention != 24*time.Hour {
		t.Fatalf("expected invalid values to use safe defaults, got %#v", config)
	}
	if config.Interface != "ap-test0" {
		t.Fatalf("expected explicit capture interface, got %q", config.Interface)
	}
}
