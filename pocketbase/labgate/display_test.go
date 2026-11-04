package labgate

import (
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
)

func TestDisplayRoleReleasesHeldTrafficAndKeepsOtherParticipantsGated(t *testing.T) {
	var display atomic.Bool
	config := testConfig()
	first := validArm().Clients[0]
	second := netip.MustParseAddr("10.0.0.151")
	config.ExcludedClient = func(ip string) bool { return display.Load() && ip == first.String() }
	controller, queue, _, _ := newTestController(t, config)
	ctx := testContext(t)
	arm := validArm()
	arm.Clients = append(arm.Clients, second)
	if _, err := controller.Arm(ctx, arm); err != nil {
		t.Fatal(err)
	}
	queue.inject(t, ctx, tcpPacket(1, 50000))
	other := tcpPacket(2, 50001)
	other.Tuple.ClientIP = second
	queue.inject(t, ctx, other)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.HeldPackets == 2 })
	display.Store(true)
	if err := controller.RefreshExclusions(ctx); err != nil {
		t.Fatal(err)
	}
	queue.assertVerdict(t, ctx, 1, VerdictAccept)
	status, err := controller.Status(ctx)
	if err != nil || status.HeldPackets != 1 || len(status.Clients) != 1 || status.Clients[0] != second.String() {
		t.Fatalf("other participant was disrupted: %+v %v", status, err)
	}
	queue.inject(t, ctx, tcpPacket(3, 50002))
	queue.assertVerdict(t, ctx, 3, VerdictAccept)
	if _, err := controller.Disarm(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Arm(ctx, validArm()); !errors.Is(err, ErrInvalidArmRequest) {
		t.Fatal("display could be armed", err)
	}
}
