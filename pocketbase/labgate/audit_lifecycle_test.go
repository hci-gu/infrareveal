package labgate

import (
	"context"
	"errors"
	"fmt"
	"myapp/testsupport"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

func TestAuditBackpressureCannotDelayKernelVerdicts(t *testing.T) {
	_, writer, seed, entered, release := blockedAuditWriter(t)
	ctx := testContext(t)
	if !writer.TryQueued(seed) {
		t.Fatal("initial audit rejected")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("audit writer did not reach persistence")
	}
	for index := 0; index < 8; index++ {
		decision := seed
		decision.ID = fmt.Sprintf("buffered-%d", index)
		if !writer.TryQueued(decision) {
			t.Fatalf("audit buffer rejected item %d before capacity", index)
		}
	}
	if writer.TryQueued(seed) {
		t.Fatal("full audit buffer accepted more work")
	}
	queue := NewFakeQueue()
	controller := lifecycleController(t, queue, nil, writer)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	arm := validArm()
	arm.SessionID = seed.SessionID
	if _, err := controller.Arm(ctx, arm); err != nil {
		t.Fatal(err)
	}
	queue.inject(t, ctx, tcpPacket(1, 50000))
	decision := waitPending(t, controller, ctx, 1)[0]
	if _, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept}); err != nil {
		t.Fatal(err)
	}
	if verdict, ok := queue.Verdict(1); !ok || verdict != VerdictAccept {
		t.Fatal("blocked persistence delayed the kernel verdict")
	}
	if drops := writer.DroppedForSession(seed.SessionID); drops != 3 {
		t.Fatalf("audit loss was not accounted for: %d", drops)
	}
	release()
	if err := writer.Flush(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAuditFlushAfterCloseStillWaitsForAcceptedWrites(t *testing.T) {
	app, writer, seed, entered, release := blockedAuditWriter(t)
	ctx := testContext(t)
	if !writer.TryQueued(seed) {
		t.Fatal("initial audit rejected")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("audit writer did not reach persistence")
	}
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.Close(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Close claimed unfinished work was drained: %v", err)
	}
	if err := writer.Flush(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Flush claimed unfinished work was drained after Close: %v", err)
	}
	release()
	if err := writer.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := app.FindAllRecords("gate_events")
	if err != nil || len(records) != 1 || records[0].GetString("decision_id") != seed.ID {
		t.Fatalf("accepted audit was not persisted: records=%v error=%v", records, err)
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestAuditFlushAndCloseDoNotBlockVerdictIntake(t *testing.T) {
	app, writer, seed, entered, release := blockedAuditWriter(t)
	ctx := testContext(t)
	if !writer.TryQueued(seed) {
		t.Fatal("initial audit rejected")
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("audit writer did not reach persistence")
	}
	for index := 0; index < 8; index++ {
		decision := seed
		decision.ID = fmt.Sprintf("buffered-%d", index)
		if !writer.TryQueued(decision) {
			t.Fatalf("audit buffer rejected item %d before capacity", index)
		}
	}
	flushCtx, cancelFlush := context.WithCancel(ctx)
	defer cancelFlush()
	flushed := make(chan error, 1)
	go func() { flushed <- writer.Flush(flushCtx) }()
	// The writer is blocked in persistence and its buffer is full, so the
	// flush barrier must wait for capacity while Close seals verdict intake.
	time.Sleep(10 * time.Millisecond)
	closeCtx, cancelClose := context.WithCancel(ctx)
	cancelClose()
	closed := make(chan error, 1)
	go func() { closed <- writer.Close(closeCtx) }()
	select {
	case err := <-closed:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("unfinished writer Close returned %v", err)
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("Close waited behind a blocked flush barrier")
	}
	accepted := make(chan bool, 1)
	go func() { accepted <- writer.TryTerminal(seed) }()
	select {
	case result := <-accepted:
		if result {
			t.Fatal("closed audit intake accepted a new verdict")
		}
	case <-time.After(250 * time.Millisecond):
		t.Fatal("audit close blocked verdict intake")
	}
	release()
	if err := <-flushed; err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if records, err := app.FindAllRecords("gate_events"); err != nil || len(records) != 9 {
		t.Fatalf("shutdown failed to drain accepted audit: count=%d error=%v", len(records), err)
	}
}

func TestRetainSessionUsesCallerTransactionAndKeepsPendingAudit(t *testing.T) {
	app, seed := newAuditFixture(t)
	collection, err := app.FindCollectionByNameOrId("gate_events")
	if err != nil {
		t.Fatal(err)
	}
	cutoff := time.Now().UTC().Truncate(time.Millisecond)
	for _, candidate := range []struct {
		id    string
		state DecisionState
		at    time.Time
	}{
		{"expired", DecisionApproved, cutoff.Add(-time.Minute)},
		{"pending", DecisionQueued, cutoff.Add(-time.Minute)},
		{"retained", DecisionApproved, cutoff},
	} {
		decision := seed
		decision.ID, decision.State, decision.QueuedAt = candidate.id, candidate.state, candidate.at
		record := core.NewRecord(collection)
		setAuditRecord(record, decision)
		if err := app.Save(record); err != nil {
			t.Fatal(err)
		}
	}
	rollback := errors.New("rollback retention")
	err = app.RunInTransaction(func(tx core.App) error {
		if err := RetainSession(tx, seed.SessionID, cutoff); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if records, err := app.FindAllRecords("gate_events"); err != nil || len(records) != 3 {
		t.Fatalf("retention escaped the caller transaction: count=%d error=%v", len(records), err)
	}
	if err := app.RunInTransaction(func(tx core.App) error { return RetainSession(tx, seed.SessionID, cutoff) }); err != nil {
		t.Fatal(err)
	}
	records, err := app.FindAllRecords("gate_events")
	if err != nil || len(records) != 2 {
		t.Fatalf("retained count=%d error=%v", len(records), err)
	}
	for _, record := range records {
		if record.GetString("decision_id") == "expired" {
			t.Fatal("expired terminal audit was retained")
		}
	}
}

func blockedAuditWriter(t *testing.T) (core.App, *AuditWriter, Decision, <-chan struct{}, func()) {
	t.Helper()
	app, decision := newAuditFixture(t)
	entered, blocked := make(chan struct{}), make(chan struct{})
	var firstWrite, releaseOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(blocked) }) }
	app.OnRecordCreate("gate_events").BindFunc(func(event *core.RecordEvent) error {
		firstWrite.Do(func() { close(entered); <-blocked })
		return event.Next()
	})
	writer := NewAuditWriter(app, 8)
	t.Cleanup(func() {
		release()
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = writer.Close(ctx)
	})
	return app, writer, decision, entered, release
}

func newAuditFixture(t *testing.T) (core.App, Decision) {
	t.Helper()
	app := testsupport.App(t)
	session := testsupport.Save(t, app, "sessions", map[string]any{
		"name":   "Audit lifecycle",
		"active": true,
	})
	packet := tcpPacket(1, 50000)
	return app, Decision{
		ID: "audit-seed", SessionID: session.Id, FlowKey: packet.Tuple.Key(), Tuple: packet.Tuple,
		ClientIP: packet.Tuple.ClientIP.String(), ClientPort: packet.Tuple.ClientPort,
		RemoteIP: packet.Tuple.RemoteIP.String(), RemotePort: packet.Tuple.RemotePort,
		Protocol: packet.Tuple.Protocol, Mode: ModeFlow, Direction: packet.Direction,
		WireBytes: packet.WireBytes, PacketCount: 1, TCPFlags: packet.TCPFlags,
		QueuedAt: packet.OccurredAt, Deadline: packet.OccurredAt.Add(time.Second), State: DecisionQueued,
	}
}
