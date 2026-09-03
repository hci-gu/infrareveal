package labgate

import (
	"context"
	"errors"
	"sync"
	"time"
)

// FakeQueue is deterministic and safe for policy, route, and demo-backend
// tests. It never stores packet bytes.
type FakeQueue struct {
	mu           sync.Mutex
	handler      func(QueuedPacket)
	ready        chan struct{}
	readyOnce    sync.Once
	closed       chan struct{}
	closeOnce    sync.Once
	verdicts     map[uint32]Verdict
	verdictOrder []uint32
	verdictError error
	verdictHook  func(uint32, Verdict)
	stats        QueueStats
}

func NewFakeQueue() *FakeQueue {
	return &FakeQueue{ready: make(chan struct{}), closed: make(chan struct{}), verdicts: make(map[uint32]Verdict)}
}

func (queue *FakeQueue) Ready() <-chan struct{} { return queue.ready }

func (queue *FakeQueue) Start(ctx context.Context, handler func(QueuedPacket)) error {
	queue.mu.Lock()
	queue.handler = handler
	queue.mu.Unlock()
	queue.readyOnce.Do(func() { close(queue.ready) })
	select {
	case <-ctx.Done():
		return nil
	case <-queue.closed:
		return nil
	}
}

func (queue *FakeQueue) SetVerdict(packetID uint32, verdict Verdict) error {
	queue.mu.Lock()
	hook, verdictErr := queue.verdictHook, queue.verdictError
	if verdictErr == nil {
		queue.verdicts[packetID] = verdict
		queue.verdictOrder = append(queue.verdictOrder, packetID)
	}
	queue.mu.Unlock()
	if hook != nil {
		hook(packetID, verdict)
	}
	return verdictErr
}

func (queue *FakeQueue) Stats() QueueStats {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return queue.stats
}

func (queue *FakeQueue) Close() error {
	queue.closeOnce.Do(func() { close(queue.closed) })
	return nil
}

func (queue *FakeQueue) Inject(ctx context.Context, packet QueuedPacket) error {
	select {
	case <-queue.ready:
	case <-ctx.Done():
		return ctx.Err()
	}
	queue.mu.Lock()
	handler := queue.handler
	queue.mu.Unlock()
	if handler == nil {
		return ErrUnavailable
	}
	handler(packet)
	return nil
}

func (queue *FakeQueue) InjectAfter(ctx context.Context, delay time.Duration, packet QueuedPacket) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-timer.C:
		return queue.Inject(ctx, packet)
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (queue *FakeQueue) Verdict(packetID uint32) (Verdict, bool) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	verdict, ok := queue.verdicts[packetID]
	return verdict, ok
}

func (queue *FakeQueue) VerdictOrder() []uint32 {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	return append([]uint32(nil), queue.verdictOrder...)
}

func (queue *FakeQueue) SetVerdictError(err error) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.verdictError = err
}

func (queue *FakeQueue) SetVerdictHook(hook func(uint32, Verdict)) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.verdictHook = hook
}

func (queue *FakeQueue) SetStats(stats QueueStats) {
	queue.mu.Lock()
	defer queue.mu.Unlock()
	queue.stats = stats
}

func (queue *FakeQueue) WaitForVerdict(ctx context.Context, packetID uint32) (Verdict, error) {
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	for {
		if verdict, ok := queue.Verdict(packetID); ok {
			return verdict, nil
		}
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-ticker.C:
		}
	}
}

var ErrFakeVerdict = errors.New("fake queue verdict failure")
