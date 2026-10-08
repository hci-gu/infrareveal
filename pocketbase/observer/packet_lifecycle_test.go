package observer

import (
	"context"
	"errors"
	"github.com/pocketbase/pocketbase/core"
	"myapp/debugtrace"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPacketCloseDrainsDirtyGenerationAfterFailedWrite(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	event := activityEvent(time.Now().UTC(), ClientToRemote, 100, 60)
	event.SessionID = session.Id
	createActivityTestFlow(t, app, session.Id, event.FlowKey)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	var failures atomic.Int32
	app.OnRecordCreate("flow_activity_chunks").BindFunc(func(e *core.RecordEvent) error {
		once.Do(func() { close(entered); <-release })
		if failures.Add(1) == 1 {
			return errors.New("transient writer failure")
		}
		return e.Next()
	})
	config := PacketActivityConfig{FlushInterval: 10 * time.Millisecond, BucketDuration: 50 * time.Millisecond, ChunkDuration: 5 * time.Second, Enabled: true}
	pipeline := startPacketPipeline(app, NewObservationScope("10.0.0.", "10.0.0.1"), func() string { return session.Id }, config, debugtrace.NopSink{}, nil)
	pipeline.events <- event
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("writer never received first generation")
	}
	event.PayloadBytes = 90
	pipeline.events <- event
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		done <- pipeline.Close(ctx)
	}()
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rows, err := app.FindAllRecords("flow_activity_chunks")
	if err != nil || len(rows) != 1 {
		t.Fatalf("chunks %d: %v", len(rows), err)
	}
	if rows[0].GetInt("packets_out") != 2 || rows[0].GetInt("payload_bytes_out") != 150 {
		t.Fatal("late generation was lost", rows[0])
	}
	if err := pipeline.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestPacketCloseTimeoutCanBeJoinedAgain(t *testing.T) {
	app := newActivityTestApp(t)
	session := createActivityTestSession(t, app, true)
	event := activityEvent(time.Now().UTC(), ClientToRemote, 100, 60)
	event.SessionID = session.Id
	createActivityTestFlow(t, app, session.Id, event.FlowKey)
	entered, release := make(chan struct{}), make(chan struct{})
	var once sync.Once
	app.OnRecordCreate("flow_activity_chunks").BindFunc(func(e *core.RecordEvent) error { once.Do(func() { close(entered); <-release }); return e.Next() })
	config := PacketActivityConfig{FlushInterval: 10 * time.Millisecond, BucketDuration: 50 * time.Millisecond, ChunkDuration: 5 * time.Second}
	pipeline := startPacketPipeline(app, NewObservationScope("10.0.0.", "10.0.0.1"), func() string { return session.Id }, config, nil, nil)
	pipeline.events <- event
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := pipeline.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("close should report blocked writer: %v", err)
	}
	close(release)
	ctx2, cancel2 := context.WithTimeout(context.Background(), time.Second)
	defer cancel2()
	if err := pipeline.Close(ctx2); err != nil {
		t.Fatal(err)
	}
}
