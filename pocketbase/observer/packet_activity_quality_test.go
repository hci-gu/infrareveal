package observer

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"myapp/debugtrace"
)

// Exercise expiry -> persistence acknowledgement -> capture status, with an
// unrelated healthy flow present. A single-caller expiry test misses the bug.
func TestUnmatchedActivityDoesNotBecomeCaptureLoss(t *testing.T) {
	for _, queueLoss := range []bool{false, true} {
		name := "unmatched-only"
		if queueLoss {
			name = "unmatched-and-queue-loss"
		}
		t.Run(name, func(t *testing.T) {
			app := newActivityTestApp(t)
			session := createActivityTestSession(t, app, true)
			now := time.Now().UTC()
			healthy := activityEvent(now, RemoteToClient, 1500, 1440)
			healthy.SessionID = session.Id
			createActivityTestFlow(t, app, session.Id, healthy.FlowKey)
			orphan := healthy
			orphan.ObservedAt = now.Add(-10 * time.Second)
			orphan.FlowKey = "tcp|10.0.0.50|63995|104.16.185.241|443"
			orphan.WireBytes, orphan.PayloadBytes = 54, 0

			ctx, cancel := context.WithCancel(context.Background())
			var workers sync.WaitGroup
			t.Cleanup(func() { cancel(); workers.Wait() })
			events := make(chan PacketActivityEvent, 2)
			requests := make(chan activityPersistRequest, 16)
			acks := make(chan activityPersistAck, 16)
			states := make(chan captureStateEvent, 1)
			var dropped atomic.Int64
			if queueLoss {
				full := make(chan PacketActivityEvent, 1)
				enqueuePacketActivity(full, healthy, &dropped)
				enqueuePacketActivity(full, healthy, &dropped)
			}
			events <- orphan
			events <- healthy
			states <- captureStateEvent{running: true}
			config := PacketActivityConfig{Enabled: true, Interface: "fixture", BucketDuration: 50 * time.Millisecond, ChunkDuration: 5 * time.Second, MaxPendingChunks: 16, FlushInterval: 10 * time.Millisecond, PendingTTL: 5 * time.Second}
			workers.Add(2)
			go func() {
				defer workers.Done()
				runPacketActivityPipeline(ctx, app, func() string { return session.Id }, config, events, requests, acks, states, &dropped, debugtrace.NopSink{})
			}()
			go func() {
				defer workers.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case request := <-requests:
						result, err := persistActivityChunk(app, request.snapshot)
						select {
						case acks <- activityPersistAck{key: request.snapshot.Key, generation: request.snapshot.Generation, result: result, err: err}:
						case <-ctx.Done():
							return
						}
					}
				}
			}()
			deadline := time.Now().Add(4 * time.Second)
			for time.Now().Before(deadline) {
				status, err := app.FindFirstRecordByFilter("flow_activity_status", "session={:session}", map[string]any{"session": session.Id})
				if err == nil && status.GetInt("unmatched_events") == 1 {
					wantDropped := 0
					if queueLoss {
						wantDropped = 1
					}
					if status.GetInt("dropped_events") != wantDropped || dropped.Load() != int64(wantDropped) {
						t.Fatalf("unmatched expiry counted as queue loss: status=%d counter=%d want=%d", status.GetInt("dropped_events"), dropped.Load(), wantDropped)
					}
					chunks, err := app.FindAllRecords("flow_activity_chunks")
					if err != nil || len(chunks) != 1 {
						t.Fatalf("expected the healthy flow's saved chunk: count=%d err=%v", len(chunks), err)
					}
					if !queueLoss && (!chunks[0].GetBool("capture_complete") || chunks[0].GetInt("dropped_events") != 0) {
						t.Fatal("unmatched flow contaminated healthy transfer quality")
					}
					if !queueLoss {
						windows, err := app.FindAllRecords("flow_activity_windows")
						if err != nil || len(windows) == 0 {
							t.Fatalf("missing capture windows: %v", err)
						}
						for _, window := range windows {
							if !window.GetBool("capture_complete") || window.GetInt("dropped_events") != 0 {
								t.Fatal("unmatched flow contaminated gateway-wide capture quality")
							}
						}
					}
					return
				}
				time.Sleep(20 * time.Millisecond)
			}
			t.Fatalf("unmatched diagnostic was not recorded separately; capture drops=%d", dropped.Load())
		})
	}
}
