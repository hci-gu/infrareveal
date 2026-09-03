package labgate

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
)

type packetOwner struct {
	queue  PacketQueue
	realID uint32
}

// MultiplexQueue presents the three isolated kernel queues as one policy edge
// while assigning process-unique packet IDs so per-queue kernel IDs can never
// collide inside the controller.
type MultiplexQueue struct {
	queues    map[Mode]PacketQueue
	ready     chan struct{}
	readyOnce sync.Once
	closeOnce sync.Once
	mu        sync.Mutex
	owners    map[uint32]packetOwner
	nextID    atomic.Uint32
}

func NewMultiplexQueue(queues map[Mode]PacketQueue) (*MultiplexQueue, error) {
	for _, mode := range []Mode{ModeFlow, ModeStrict, ModeDNS} {
		if queues[mode] == nil {
			return nil, fmt.Errorf("missing %s packet queue", mode)
		}
	}
	copyQueues := make(map[Mode]PacketQueue, len(queues))
	for mode, queue := range queues {
		copyQueues[mode] = queue
	}
	return &MultiplexQueue{queues: copyQueues, ready: make(chan struct{}), owners: make(map[uint32]packetOwner)}, nil
}

func (queue *MultiplexQueue) Ready() <-chan struct{} { return queue.ready }

func (queue *MultiplexQueue) Start(ctx context.Context, handler func(QueuedPacket)) error {
	runCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	type result struct {
		mode Mode
		err  error
	}
	results := make(chan result, len(queue.queues))
	ready := make(chan Mode, len(queue.queues))
	for mode, child := range queue.queues {
		mode, child := mode, child
		go func() {
			go func() {
				results <- result{mode, child.Start(runCtx, func(packet QueuedPacket) {
					virtualID := queue.nextID.Add(1)
					queue.mu.Lock()
					queue.owners[virtualID] = packetOwner{queue: child, realID: packet.ID}
					queue.mu.Unlock()
					packet.ID, packet.QueueMode = virtualID, mode
					handler(packet)
				})}
			}()
			if readyChild, ok := child.(ReadyPacketQueue); ok {
				select {
				case <-readyChild.Ready():
					ready <- mode
				case <-runCtx.Done():
				}
			} else {
				ready <- mode
			}
		}()
	}
	readyCount := 0
	for readyCount < len(queue.queues) {
		select {
		case <-ready:
			readyCount++
		case finished := <-results:
			if finished.err != nil {
				return fmt.Errorf("%s queue failed before readiness: %w", finished.mode, finished.err)
			}
			return fmt.Errorf("%s queue stopped before readiness", finished.mode)
		case <-runCtx.Done():
			return nil
		}
	}
	queue.readyOnce.Do(func() { close(queue.ready) })
	select {
	case finished := <-results:
		if finished.err != nil {
			return fmt.Errorf("%s queue failed: %w", finished.mode, finished.err)
		}
		return nil
	case <-runCtx.Done():
		return nil
	}
}

func (queue *MultiplexQueue) SetVerdict(packetID uint32, verdict Verdict) error {
	queue.mu.Lock()
	owner, ok := queue.owners[packetID]
	if ok {
		delete(queue.owners, packetID)
	}
	queue.mu.Unlock()
	if !ok {
		return ErrDecisionNotFound
	}
	return owner.queue.SetVerdict(owner.realID, verdict)
}

func (queue *MultiplexQueue) Stats() QueueStats {
	stats := QueueStats{}
	for _, child := range queue.queues {
		value := child.Stats()
		stats.QueueDepth += value.QueueDepth
		stats.KernelDrops += value.KernelDrops
		stats.UserDrops += value.UserDrops
		stats.ParseBypass += value.ParseBypass
	}
	return stats
}

func (queue *MultiplexQueue) Close() error {
	var result error
	queue.closeOnce.Do(func() {
		for _, child := range queue.queues {
			result = errors.Join(result, child.Close())
		}
		queue.mu.Lock()
		clear(queue.owners)
		queue.mu.Unlock()
	})
	return result
}

var _ ReadyPacketQueue = (*MultiplexQueue)(nil)
