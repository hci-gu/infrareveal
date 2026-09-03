package labgate

import (
	"context"
	"testing"
	"time"
)

func TestMultiplexQueueOwnsCollidingKernelPacketIDs(t *testing.T) {
	children := map[Mode]PacketQueue{
		ModeFlow: NewFakeQueue(), ModeStrict: NewFakeQueue(), ModeDNS: NewFakeQueue(),
	}
	queue, err := NewMultiplexQueue(children)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	packets := make(chan QueuedPacket, 2)
	started := make(chan error, 1)
	go func() { started <- queue.Start(ctx, func(packet QueuedPacket) { packets <- packet }) }()
	select {
	case <-queue.Ready():
	case <-time.After(time.Second):
		t.Fatal("multiplex queue did not become ready")
	}
	for _, mode := range []Mode{ModeFlow, ModeStrict} {
		if err := children[mode].(*FakeQueue).Inject(ctx, QueuedPacket{ID: 7}); err != nil {
			t.Fatal(err)
		}
	}
	first, second := <-packets, <-packets
	if first.ID == second.ID || first.QueueMode == second.QueueMode {
		t.Fatalf("virtual IDs/modes were not isolated: %+v %+v", first, second)
	}
	if err := queue.SetVerdict(first.ID, VerdictAccept); err != nil {
		t.Fatal(err)
	}
	if err := queue.SetVerdict(second.ID, VerdictDrop); err != nil {
		t.Fatal(err)
	}
	for _, packet := range []QueuedPacket{first, second} {
		child := children[packet.QueueMode].(*FakeQueue)
		if _, ok := child.Verdict(7); !ok {
			t.Fatalf("verdict was not routed to %s child", packet.QueueMode)
		}
	}
	cancel()
	select {
	case err := <-started:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("multiplex queue did not stop")
	}
}

func TestMultiplexQueueAggregatesStats(t *testing.T) {
	flow, strict, dns := NewFakeQueue(), NewFakeQueue(), NewFakeQueue()
	flow.SetStats(QueueStats{QueueDepth: 1, KernelDrops: 2})
	strict.SetStats(QueueStats{QueueDepth: 3, UserDrops: 4})
	dns.SetStats(QueueStats{ParseBypass: 5})
	queue, err := NewMultiplexQueue(map[Mode]PacketQueue{ModeFlow: flow, ModeStrict: strict, ModeDNS: dns})
	if err != nil {
		t.Fatal(err)
	}
	stats := queue.Stats()
	if stats.QueueDepth != 4 || stats.KernelDrops != 2 || stats.UserDrops != 4 || stats.ParseBypass != 5 {
		t.Fatalf("aggregated stats = %+v", stats)
	}
}
