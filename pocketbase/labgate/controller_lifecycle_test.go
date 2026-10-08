package labgate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"
)

func TestControllerRequiresQueueReadinessBeforeArming(t *testing.T) {
	ready := make(chan struct{})
	queue := &delayedReadyQueue{FakeQueue: NewFakeQueue(), ready: ready}
	controller := lifecycleController(t, queue, nil, nil)
	ctx := testContext(t)
	status, err := controller.Status(ctx)
	if err != nil || status.ListenerReady {
		t.Fatalf("listener is not ready: %+v %v", status, err)
	}
	if _, err := controller.Arm(ctx, validArm()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("armed before readiness: %v", err)
	}
	close(ready)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	mustArm(t, controller, ctx)
}

func TestUnexpectedQueueExitDrainsDecisionsAndClearsReadiness(t *testing.T) {
	queue := &controlledQueue{FakeQueue: NewFakeQueue(), stop: make(chan struct{})}
	audit := &auditCollector{}
	controller := lifecycleController(t, queue, nil, audit)
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	mustArm(t, controller, ctx)
	for id := uint32(1); id <= 2; id++ {
		if err := queue.Inject(ctx, tcpPacket(id, uint16(50000+id))); err != nil {
			t.Fatal(err)
		}
	}
	waitPending(t, controller, ctx, 2)
	close(queue.stop)
	eventually(t, func() bool {
		status, _ := controller.Status(ctx)
		return status.State == StateDegraded && !status.ListenerReady && status.HeldPackets == 0
	})
	for id := uint32(1); id <= 2; id++ {
		if verdict, ok := queue.Verdict(id); !ok || verdict != VerdictAccept {
			t.Fatalf("listener failure left packet %d held", id)
		}
	}
	if terminal := audit.terminal(); len(terminal) != 2 || terminal[0].Source != SourceSystem || terminal[1].Source != SourceSystem {
		t.Fatalf("listener failure audit: %+v", terminal)
	}
}

func TestControllerCloseJoinsQueueCompletion(t *testing.T) {
	release := make(chan struct{})
	queue := &controlledQueue{FakeQueue: NewFakeQueue(), release: release}
	controller := lifecycleController(t, queue, nil, nil)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	closed := make(chan error, 1)
	go func() { closed <- controller.Close(ctx) }()
	select {
	case <-queue.closed:
	case <-ctx.Done():
		t.Fatal("controller did not close its queue")
	}
	select {
	case err := <-closed:
		t.Fatalf("Close returned before the queue worker completed: %v", err)
	default:
	}
	close(release)
	if err := <-closed; err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentArrivalsAndShutdownReleaseEveryPacket(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	start := make(chan struct{})
	var producers sync.WaitGroup
	for producer := uint32(0); producer < 4; producer++ {
		producers.Add(1)
		go func() {
			defer producers.Done()
			<-start
			for index := uint32(1); index <= 250; index++ {
				_ = queue.Inject(ctx, tcpPacket(producer*250+index, 50000))
			}
		}()
	}
	close(start)
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
	producers.Wait()
	for id := uint32(1); id <= 1000; id++ {
		if verdict, ok := queue.Verdict(id); !ok || verdict != VerdictAccept {
			t.Fatalf("packet %d was lost across shutdown: verdict=%q present=%t", id, verdict, ok)
		}
	}
}

func TestControllerCloseCanJoinAfterCallerTimeout(t *testing.T) {
	release := make(chan struct{})
	queue := &controlledQueue{FakeQueue: NewFakeQueue(), release: release}
	controller := lifecycleController(t, queue, nil, nil)
	defer close(release)
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := controller.Close(shortCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished queue did not time out: %v", err)
	}
	// Closing is still in progress. A later caller joins the same shutdown,
	// rather than inheriting the earlier caller's timeout as a permanent error.
	closed := make(chan error, 1)
	go func() { closed <- controller.Close(ctx) }()
	select {
	case err := <-closed:
		t.Fatalf("second Close returned before the queue worker completed: %v", err)
	default:
	}
	release <- struct{}{}
	if err := <-closed; err != nil {
		t.Fatalf("second Close retained the caller timeout: %v", err)
	}
}

func TestControllerCloseTimeoutKeepsQueueAvailableForShutdown(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	queue := NewFakeQueue()
	rules := &lifecycleRules{clear: func() error {
		close(entered)
		<-release
		return nil
	}}
	controller := lifecycleController(t, queue, rules, nil)
	defer close(release)
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	shortCtx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := controller.Close(shortCtx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("unfinished cleanup did not time out: %v", err)
	}
	select {
	case <-entered:
	case <-ctx.Done():
		t.Fatal("shutdown did not reach rule cleanup")
	}
	select {
	case <-queue.closed:
		t.Fatal("caller timeout closed queue before rule cleanup completed")
	default:
	}
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	if verdict, ok := queue.Verdict(1); !ok || verdict != VerdictAccept {
		t.Fatal("late packet was not accepted while shutdown was in progress")
	}
	release <- struct{}{}
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestShutdownAcceptsCleanupArrivalsAndRetainsCleanupErrors(t *testing.T) {
	queue := NewFakeQueue()
	cleanupErr := errors.New("cleanup failed")
	rules := &lifecycleRules{cleanupErr: cleanupErr}
	controller := lifecycleController(t, queue, rules, nil)
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	mustArm(t, controller, ctx)
	packet := tcpPacket(100, 51000)
	rules.clear = func() error {
		if err := queue.Inject(ctx, packet); err != nil {
			return err
		}
		if verdict, ok := queue.Verdict(packet.ID); !ok || verdict != VerdictAccept {
			return errors.New("new packet was held during shutdown cleanup")
		}
		return nil
	}
	for attempt := 0; attempt < 2; attempt++ {
		if err := controller.Close(ctx); !errors.Is(err, cleanupErr) {
			t.Fatalf("Close did not retain cleanup error: %v", err)
		}
	}
	if rules.clears != 1 || rules.cleanups != 1 {
		t.Fatalf("shutdown repeated rule operations: clear=%d cleanup=%d", rules.clears, rules.cleanups)
	}
}

func TestParentCancellationCleansRulesAndReleasesHeldPackets(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	defer cancel()
	queue, rules := NewFakeQueue(), &lifecycleRules{}
	controller, err := NewController(parent, testConfig(), queue, rules, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	mustArm(t, controller, ctx)
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	waitPending(t, controller, ctx, 1)
	cancel()
	if err := controller.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if verdict, ok := queue.Verdict(1); !ok || verdict != VerdictAccept || rules.clears != 1 || rules.cleanups != 1 {
		t.Fatalf("cancelled controller did not finish shutdown: verdict=%q clear=%d cleanup=%d", verdict, rules.clears, rules.cleanups)
	}
}

func TestVerdictFailureDuringDrainFinishesEachDecisionOnce(t *testing.T) {
	controller, queue, _, audit := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	for id := uint32(1); id <= 3; id++ {
		if err := queue.Inject(ctx, tcpPacket(id, uint16(50000+id))); err != nil {
			t.Fatal(err)
		}
	}
	waitPending(t, controller, ctx, 3)
	queue.SetVerdictError(ErrFakeVerdict)
	status, err := controller.Drain(ctx)
	if err != nil || status.HeldPackets != 0 || status.PendingFlows != 0 || status.VerdictErrors != 3 {
		t.Fatalf("failed drain ownership: %+v %v", status, err)
	}
	terminal := audit.terminal()
	seen := make(map[string]bool)
	for _, decision := range terminal {
		if seen[decision.ID] || decision.State != DecisionDrained || decision.Verdict != VerdictAccept {
			t.Fatalf("invalid or repeated terminal audit: %+v", terminal)
		}
		seen[decision.ID] = true
	}
	if len(terminal) != 3 {
		t.Fatalf("expected one terminal audit per decision, got %d", len(terminal))
	}
}

func lifecycleController(t *testing.T, queue PacketQueue, rules RuleManager, audit AuditSink) *Controller {
	t.Helper()
	controller, err := NewController(context.Background(), testConfig(), queue, rules, nil, audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = controller.Close(ctx)
	})
	return controller
}

type delayedReadyQueue struct {
	*FakeQueue
	ready chan struct{}
}

func (queue *delayedReadyQueue) Ready() <-chan struct{} { return queue.ready }

type controlledQueue struct {
	*FakeQueue
	stop     chan struct{}
	release  chan struct{}
	finished chan struct{}
}

func (queue *controlledQueue) Start(ctx context.Context, handler func(QueuedPacket)) error {
	if queue.finished != nil {
		defer close(queue.finished)
	}
	queue.mu.Lock()
	queue.handler = handler
	queue.mu.Unlock()
	queue.readyOnce.Do(func() { close(queue.ready) })
	select {
	case <-ctx.Done():
	case <-queue.closed:
	case <-queue.stop:
	}
	if queue.release != nil {
		<-queue.release
	}
	return nil
}

type lifecycleRules struct {
	clear      func() error
	cleanupErr error
	clears     int
	cleanups   int
}

func (*lifecycleRules) Prepare(context.Context) error                 { return nil }
func (*lifecycleRules) Activate(context.Context, RuleSelection) error { return nil }
func (*lifecycleRules) Ready() bool                                   { return true }
func (rules *lifecycleRules) ClearClients(context.Context) error {
	rules.clears++
	if rules.clear != nil {
		return rules.clear()
	}
	return nil
}
func (rules *lifecycleRules) Cleanup(context.Context) error {
	rules.cleanups++
	if rules.cleanupErr != nil {
		return fmt.Errorf("remove gate rules: %w", rules.cleanupErr)
	}
	return nil
}
