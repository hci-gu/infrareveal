package labgate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"myapp/debugtrace"
	"myapp/netmeta"
)

func TestControllerStateMachineAndArmGuards(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	if _, err := controller.Pause(ctx); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("pause off: %v", err)
	}
	status, err := controller.Arm(ctx, validArm())
	if err != nil || status.State != StateActive || !status.Armed {
		t.Fatalf("arm: %+v %v", status, err)
	}
	if _, err := controller.Arm(ctx, validArm()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("rearm: %v", err)
	}
	status, err = controller.Pause(ctx)
	if err != nil || status.State != StatePaused || !status.Paused {
		t.Fatalf("pause: %+v %v", status, err)
	}
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	if verdict, err := queue.WaitForVerdict(ctx, 1); err != nil || verdict != VerdictAccept {
		t.Fatalf("paused fail-open = %q, %v", verdict, err)
	}
	status, err = controller.Drain(ctx)
	if err != nil || status.State != StatePaused {
		t.Fatalf("drain: %+v %v", status, err)
	}
	status, err = controller.Resume(ctx)
	if err != nil || status.State != StateActive {
		t.Fatalf("resume: %+v %v", status, err)
	}
	status, err = controller.Disarm(ctx)
	if err != nil || status.State != StateOff || len(status.Clients) != 0 {
		t.Fatalf("disarm: %+v %v", status, err)
	}
	if status, err = controller.Disarm(ctx); err != nil || status.State != StateOff {
		t.Fatalf("idempotent disarm: %+v %v", status, err)
	}

	cases := []struct {
		name   string
		mutate func(*Config)
		want   error
	}{
		{"disabled", func(config *Config) { config.Enabled = false }, ErrDisabled},
		{"fail-closed", func(config *Config) { config.FailOpen = false }, ErrInvalidArmRequest},
		{"no token", func(config *Config) { config.ControlTokenFile = "" }, ErrInvalidArmRequest},
	}
	for _, item := range cases {
		t.Run(item.name, func(t *testing.T) {
			config := testConfig()
			item.mutate(&config)
			candidate, _, _, _ := newTestController(t, config)
			_, err := candidate.Arm(testContext(t), validArm())
			if !errors.Is(err, item.want) {
				t.Fatalf("arm error = %v, want %v", err, item.want)
			}
		})
	}
}

func TestDisarmRuleFailureStaysVisibleFailOpenAndRetryable(t *testing.T) {
	config := testConfig()
	queue, rules := NewFakeQueue(), &flakyRuleManager{clearFailures: 1}
	controller, err := NewControllerWithRules(context.Background(), config, queue, rules, &traceCollector{}, &auditCollector{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = controller.Close(closeCtx)
	})
	ctx := testContext(t)
	eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	if _, err := controller.Arm(ctx, validArm()); err != nil {
		t.Fatal(err)
	}
	status, err := controller.Disarm(ctx)
	if err == nil || status.State != StateDegraded || !status.Armed || len(status.Clients) != 1 {
		t.Fatalf("failed cleanup must remain visible and retryable: %+v %v", status, err)
	}
	packet := tcpPacket(900, 50900)
	if err := queue.Inject(ctx, packet); err != nil {
		t.Fatal(err)
	}
	if verdict, err := queue.WaitForVerdict(ctx, packet.ID); err != nil || verdict != VerdictAccept {
		t.Fatalf("degraded cleanup must fail open: %q %v", verdict, err)
	}
	status, err = controller.Disarm(ctx)
	if err != nil || status.State != StateOff || status.Armed {
		t.Fatalf("cleanup retry = %+v %v", status, err)
	}
}

func TestTCPAndUDPGroupingCachingAndTupleIsolation(t *testing.T) {
	controller, queue, traces, audit := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	for _, packet := range []QueuedPacket{tcpPacket(1, 50000), tcpPacket(2, 50000)} {
		if err := queue.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
	}
	var pending []Decision
	eventually(t, func() bool {
		pending, _ = controller.Pending(ctx)
		return len(pending) == 1 && pending[0].PacketCount == 2
	})
	if pending[0].PacketCount != 2 {
		t.Fatalf("packet count = %d", pending[0].PacketCount)
	}
	result, err := controller.Decide(ctx, DecisionCommand{DecisionID: pending[0].ID, Verdict: VerdictAccept, Actor: "tester"})
	if err != nil || result.Decision.State != DecisionApproved {
		t.Fatalf("approve: %+v %v", result, err)
	}
	for _, id := range []uint32{1, 2} {
		if verdict, err := queue.WaitForVerdict(ctx, id); err != nil || verdict != VerdictAccept {
			t.Fatalf("packet %d = %q %v", id, verdict, err)
		}
	}
	if err := queue.Inject(ctx, tcpPacket(3, 50000)); err != nil {
		t.Fatal(err)
	}
	if verdict, err := queue.WaitForVerdict(ctx, 3); err != nil || verdict != VerdictAccept {
		t.Fatalf("cached = %q %v", verdict, err)
	}
	if err := queue.Inject(ctx, tcpPacket(4, 50001)); err != nil {
		t.Fatal(err)
	}
	if decisions := waitPending(t, controller, ctx, 1); decisions[0].FlowKey == pending[0].FlowKey {
		t.Fatal("different client source ports were grouped")
	}
	if len(audit.queued()) != 2 || traces.countKind(debugtrace.KindGate) < 3 {
		t.Fatalf("audit=%d trace=%d", len(audit.queued()), traces.countKind(debugtrace.KindGate))
	}

	if _, err := controller.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.Resume(ctx); err != nil {
		t.Fatal(err)
	}
	if err := queue.Inject(ctx, udpPacket(10, 53000)); err != nil {
		t.Fatal(err)
	}
	if err := queue.Inject(ctx, udpPacket(11, 53000)); err != nil {
		t.Fatal(err)
	}
	var udp []Decision
	eventually(t, func() bool {
		udp, _ = controller.Pending(ctx)
		return len(udp) == 1 && udp[0].PacketCount == 2
	})
	if udp[0].PacketCount != 2 || udp[0].Protocol != "udp" {
		t.Fatalf("UDP grouping: %+v", udp[0])
	}
}

func TestRejectAndRepeatedDecisionAreIdempotent(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	decision := waitPending(t, controller, ctx, 1)[0]
	first, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictDrop})
	if err != nil || first.AlreadyTerminal {
		t.Fatalf("first: %+v %v", first, err)
	}
	second, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictDrop})
	if err != nil || !second.AlreadyTerminal || second.Decision.State != DecisionRejected {
		t.Fatalf("repeat: %+v %v", second, err)
	}
	if verdict, _ := queue.Verdict(1); verdict != VerdictDrop {
		t.Fatalf("verdict = %q", verdict)
	}
	if err := queue.Inject(ctx, tcpPacket(2, 50000)); err != nil {
		t.Fatal(err)
	}
	if verdict, err := queue.WaitForVerdict(ctx, 2); err != nil || verdict != VerdictDrop {
		t.Fatalf("cached rejection = %q %v", verdict, err)
	}
}

func TestArrivalDuringVerdictUsesTerminalCache(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	decision := waitPending(t, controller, ctx, 1)[0]
	var once sync.Once
	queue.SetVerdictHook(func(_ uint32, _ Verdict) {
		once.Do(func() { _ = queue.Inject(ctx, tcpPacket(2, 50000)) })
	})
	if _, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept}); err != nil {
		t.Fatal(err)
	}
	if verdict, err := queue.WaitForVerdict(ctx, 2); err != nil || verdict != VerdictAccept {
		t.Fatalf("late packet = %q %v", verdict, err)
	}
	status, err := controller.Status(ctx)
	if err != nil || status.HeldPackets != 0 {
		t.Fatalf("unowned packet: %+v %v", status, err)
	}
}

func TestWatchdogExpiresAndReleases(t *testing.T) {
	config := testConfig()
	config.FlowTimeout = 100 * time.Millisecond
	controller, queue, _, audit := newTestController(t, config)
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	if err := queue.Inject(ctx, tcpPacket(1, 50000)); err != nil {
		t.Fatal(err)
	}
	decision := waitPending(t, controller, ctx, 1)[0]
	if verdict, err := queue.WaitForVerdict(ctx, 1); err != nil || verdict != VerdictAccept {
		t.Fatalf("watchdog = %q %v", verdict, err)
	}
	result, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept})
	if err != nil || !result.AlreadyTerminal || result.Decision.State != DecisionExpired || result.Decision.Source != SourceWatchdog {
		t.Fatalf("terminal watchdog: %+v %v", result, err)
	}
	status, _ := controller.Status(ctx)
	if status.WatchdogReleases != 1 || len(audit.terminal()) != 1 {
		t.Fatalf("status=%+v audit=%d", status, len(audit.terminal()))
	}
}

func TestPendingAndHeldCapacityFailOpen(t *testing.T) {
	t.Run("pending flows", func(t *testing.T) {
		config := testConfig()
		config.MaxPendingFlows = 1
		controller, queue, _, audit := newTestController(t, config)
		ctx := testContext(t)
		mustArm(t, controller, ctx)
		_ = queue.Inject(ctx, tcpPacket(1, 50000))
		waitPending(t, controller, ctx, 1)
		_ = queue.Inject(ctx, tcpPacket(2, 50001))
		if verdict, err := queue.WaitForVerdict(ctx, 2); err != nil || verdict != VerdictAccept {
			t.Fatalf("overflow = %q %v", verdict, err)
		}
		status, _ := controller.Status(ctx)
		if status.OverflowBypasses != 1 || status.PendingFlows != 1 {
			t.Fatalf("status = %+v", status)
		}
		if terminal := audit.terminal(); len(terminal) != 1 || terminal[0].State != DecisionBypassed || terminal[0].Source != SourceOverflow {
			t.Fatalf("durable overflow audit = %+v", terminal)
		}
	})
	t.Run("held packets", func(t *testing.T) {
		config := testConfig()
		config.MaxHeldPackets = 8
		controller, queue, _, audit := newTestController(t, config)
		ctx := testContext(t)
		mustArm(t, controller, ctx)
		for id := uint32(1); id <= 9; id++ {
			_ = queue.Inject(ctx, tcpPacket(id, 50000))
		}
		if verdict, err := queue.WaitForVerdict(ctx, 9); err != nil || verdict != VerdictAccept {
			t.Fatalf("held overflow = %q %v", verdict, err)
		}
		status, _ := controller.Status(ctx)
		if status.HeldPackets != 8 || status.OverflowBypasses != 1 {
			t.Fatalf("status = %+v", status)
		}
		if terminal := audit.terminal(); len(terminal) != 1 || terminal[0].State != DecisionBypassed || terminal[0].Source != SourceOverflow {
			t.Fatalf("durable held-packet overflow audit = %+v", terminal)
		}
	})
}

func TestVerdictFailureDegradesAndClearsOwnership(t *testing.T) {
	controller, queue, traces, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	_ = queue.Inject(ctx, tcpPacket(1, 50000))
	decision := waitPending(t, controller, ctx, 1)[0]
	queue.SetVerdictError(ErrFakeVerdict)
	if _, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept}); err != nil {
		t.Fatal(err)
	}
	status, err := controller.Status(ctx)
	if err != nil || status.State != StateDegraded || status.HeldPackets != 0 || status.PendingFlows != 0 || status.VerdictErrors == 0 {
		t.Fatalf("degraded status = %+v, %v", status, err)
	}
	if traces.countKind(debugtrace.KindHealth) == 0 {
		t.Fatal("missing health trace")
	}
}

func TestShutdownDrainsWithinDeadline(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	mustArm(t, controller, ctx)
	for id := uint32(1); id <= 5; id++ {
		_ = queue.Inject(ctx, tcpPacket(id, 50000))
	}
	waitPending(t, controller, ctx, 1)
	closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := controller.Close(closeCtx); err != nil {
		t.Fatal(err)
	}
	for id := uint32(1); id <= 5; id++ {
		if verdict, ok := queue.Verdict(id); !ok || verdict != VerdictAccept {
			t.Fatalf("packet %d remained held", id)
		}
	}
}

func TestStrictModeQueuesEveryPacketAndAcceptsNext(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	tuple, _ := netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), 50000, netip.MustParseAddr("1.1.1.1"), 443)
	arm := ArmRequest{SessionID: "session-1", Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP}, Strict: &tuple}
	if _, err := controller.Arm(ctx, arm); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.AcceptNext(ctx, 2, "tester"); err != nil {
		t.Fatal(err)
	}
	for id, direction := range []netmeta.Direction{netmeta.ClientToRemote, netmeta.RemoteToClient} {
		packet := QueuedPacket{ID: uint32(id + 1), QueueMode: ModeStrict, Tuple: tuple, Direction: direction, WireBytes: 60, PayloadBytes: 3, TCPFlags: 0x10, OccurredAt: time.Now()}
		if err := queue.Inject(ctx, packet); err != nil {
			t.Fatal(err)
		}
		if verdict, err := queue.WaitForVerdict(ctx, packet.ID); err != nil || verdict != VerdictAccept {
			t.Fatalf("strict auto verdict = %q %v", verdict, err)
		}
	}
	status, _ := controller.Status(ctx)
	if status.StrictAutoAccept != 0 || status.PendingFlows != 0 {
		t.Fatalf("strict status = %+v", status)
	}
	packet := QueuedPacket{ID: 3, QueueMode: ModeStrict, Tuple: tuple, Direction: netmeta.ClientToRemote, WireBytes: 64, PayloadBytes: 7, TCPFlags: 0x18, OccurredAt: time.Now()}
	_ = queue.Inject(ctx, packet)
	decision := waitPending(t, controller, ctx, 1)[0]
	if decision.PacketCount != 1 || decision.Direction != netmeta.ClientToRemote || decision.WireBytes != 64 || decision.PayloadBytes != 7 {
		t.Fatalf("strict decision collapsed packet metadata: %+v", decision)
	}
}

func TestStrictModeRefusesWildcardOrMultipleClientsAndExpires(t *testing.T) {
	config := testConfig()
	config.EstablishedTimeout = 100 * time.Millisecond
	controller, queue, _, _ := newTestController(t, config)
	ctx := testContext(t)
	tuple, _ := netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), 50000, netip.MustParseAddr("1.1.1.1"), 443)
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP}}); !errors.Is(err, ErrInvalidArmRequest) {
		t.Fatalf("missing strict tuple = %v", err)
	}
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP, netip.MustParseAddr("10.0.0.3")}, Strict: &tuple}); !errors.Is(err, ErrInvalidArmRequest) {
		t.Fatalf("multiple strict clients = %v", err)
	}
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP}, Strict: &tuple}); err != nil {
		t.Fatal(err)
	}
	packet := QueuedPacket{ID: 10, QueueMode: ModeStrict, Tuple: tuple, Direction: netmeta.ClientToRemote, OccurredAt: time.Now()}
	_ = queue.Inject(ctx, packet)
	decision := waitPending(t, controller, ctx, 1)[0]
	if verdict, err := queue.WaitForVerdict(ctx, packet.ID); err != nil || verdict != VerdictAccept {
		t.Fatalf("strict watchdog = %q %v", verdict, err)
	}
	terminal, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept})
	if err != nil || terminal.Decision.State != DecisionExpired {
		t.Fatalf("strict terminal = %+v %v", terminal, err)
	}
}

func TestDNSModeGroupsRetriesAndRejectsUnselectedClients(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeDNS, Clients: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}); err != nil {
		t.Fatal(err)
	}
	dnsPacket := func(id uint32, client string) QueuedPacket {
		tuple, _ := netmeta.NewFlowTuple("udp", netip.MustParseAddr(client), 53000, netip.MustParseAddr("10.0.0.1"), 53)
		return QueuedPacket{ID: id, QueueMode: ModeDNS, Tuple: tuple, Direction: netmeta.ClientToRemote, OccurredAt: time.Now()}
	}
	_ = queue.Inject(ctx, dnsPacket(20, "10.0.0.2"))
	_ = queue.Inject(ctx, dnsPacket(21, "10.0.0.2"))
	var decisions []Decision
	eventually(t, func() bool {
		decisions, _ = controller.Pending(ctx)
		return len(decisions) == 1 && decisions[0].PacketCount == 2
	})
	if decisions[0].PacketCount != 2 || decisions[0].Mode != ModeDNS || decisions[0].Deadline.Sub(decisions[0].QueuedAt) != 2*time.Second {
		t.Fatalf("DNS grouping/deadline = %+v", decisions[0])
	}
	firstDecisionID := decisions[0].ID
	if _, err := controller.Decide(ctx, DecisionCommand{DecisionID: firstDecisionID, Verdict: VerdictAccept}); err != nil {
		t.Fatal(err)
	}
	_ = queue.Inject(ctx, dnsPacket(23, "10.0.0.2"))
	decisions = waitPending(t, controller, ctx, 1)
	if decisions[0].ID == firstDecisionID {
		t.Fatal("a terminal DNS decision silently cached approval for a later datagram")
	}
	_ = queue.Inject(ctx, dnsPacket(22, "10.0.0.3"))
	if verdict, err := queue.WaitForVerdict(ctx, 22); err != nil || verdict != VerdictAccept {
		t.Fatalf("unselected DNS client = %q %v", verdict, err)
	}
}

func TestStrictTCPFinishAutomaticallyDisarms(t *testing.T) {
	controller, queue, _, _ := newTestController(t, testConfig())
	ctx := testContext(t)
	tuple, _ := netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), 50000, netip.MustParseAddr("1.1.1.1"), 443)
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeStrict, Clients: []netip.Addr{tuple.ClientIP}, Strict: &tuple}); err != nil {
		t.Fatal(err)
	}
	packet := QueuedPacket{ID: 30, QueueMode: ModeStrict, Tuple: tuple, Direction: netmeta.RemoteToClient, TCPFlags: 0x01, OccurredAt: time.Now()}
	_ = queue.Inject(ctx, packet)
	decision := waitPending(t, controller, ctx, 1)[0]
	if _, err := controller.Decide(ctx, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept}); err != nil {
		t.Fatal(err)
	}
	status, _ := controller.Status(ctx)
	if status.State != StateOff || status.Armed || len(status.Clients) != 0 {
		t.Fatalf("strict finish did not disarm: %+v", status)
	}
}

func TestThirtyClientAdmissionPressureRemainsBoundedAndFailsOpen(t *testing.T) {
	config := testConfig()
	config.MaxPendingFlows = 128
	config.MaxHeldPackets = 256
	config.FlowTimeout = 5 * time.Second
	controller, queue, _, _ := newTestController(t, config)
	ctx := testContext(t)
	clients := make([]netip.Addr, 0, 30)
	for client := 2; client < 32; client++ {
		clients = append(clients, netip.MustParseAddr(fmt.Sprintf("10.0.0.%d", client)))
	}
	if _, err := controller.Arm(ctx, ArmRequest{SessionID: "session-1", Mode: ModeFlow, Clients: clients}); err != nil {
		t.Fatal(err)
	}
	packetID := uint32(1)
	for _, client := range clients {
		for flow := 0; flow < 5; flow++ {
			tuple, _ := netmeta.NewFlowTuple("udp", client, uint16(40_000+flow), netip.MustParseAddr("1.1.1.1"), uint16(4000+flow))
			_ = queue.Inject(ctx, QueuedPacket{ID: packetID, Tuple: tuple, Direction: netmeta.ClientToRemote, OccurredAt: time.Now()})
			packetID++
		}
	}
	eventually(t, func() bool {
		status, _ := controller.Status(ctx)
		return status.PendingFlows == 128 && status.HeldPackets == 128 && status.OverflowBypasses == 22
	})
	if _, err := controller.ApproveAll(ctx, "load test", "bounded release"); err != nil {
		t.Fatal(err)
	}
	status, _ := controller.Status(ctx)
	if status.PendingFlows != 0 || status.HeldPackets != 0 {
		t.Fatalf("load drain left ownership: %+v", status)
	}
}

func testConfig() Config {
	return Config{
		Enabled: true, QueueNumber: 42, StrictQueueNumber: 43, DNSQueueNumber: 44,
		MaxPendingFlows: 8, MaxHeldPackets: 16, FlowTimeout: time.Second,
		EstablishedTimeout: 500 * time.Millisecond, DNSTimeout: 2 * time.Second,
		DecisionCache: time.Second, FailOpen: true, ControlTokenFile: "/configured/token",
	}
}

func validArm() ArmRequest {
	return ArmRequest{SessionID: "session-1", Mode: ModeFlow, Clients: []netip.Addr{netip.MustParseAddr("10.0.0.2")}}
}

func tcpPacket(id uint32, sourcePort uint16) QueuedPacket {
	tuple, _ := netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), sourcePort, netip.MustParseAddr("1.1.1.1"), 443)
	return QueuedPacket{ID: id, Tuple: tuple, Direction: netmeta.ClientToRemote, WireBytes: 60, TCPFlags: 0x02, OccurredAt: time.Now()}
}

func udpPacket(id uint32, sourcePort uint16) QueuedPacket {
	tuple, _ := netmeta.NewFlowTuple("udp", netip.MustParseAddr("10.0.0.2"), sourcePort, netip.MustParseAddr("1.1.1.1"), 443)
	return QueuedPacket{ID: id, Tuple: tuple, Direction: netmeta.ClientToRemote, WireBytes: 80, PayloadBytes: 52, OccurredAt: time.Now()}
}

type flakyRuleManager struct {
	clearFailures int
}

func (*flakyRuleManager) Prepare(context.Context) error                  { return nil }
func (*flakyRuleManager) SetClients(context.Context, []netip.Addr) error { return nil }
func (rules *flakyRuleManager) ClearClients(context.Context) error {
	if rules.clearFailures > 0 {
		rules.clearFailures--
		return errors.New("injected client-set cleanup failure")
	}
	return nil
}
func (*flakyRuleManager) Cleanup(context.Context) error { return nil }
func (*flakyRuleManager) Ready() bool                   { return true }

func newTestController(t *testing.T, config Config) (*Controller, *FakeQueue, *traceCollector, *auditCollector) {
	t.Helper()
	queue, traces, audit := NewFakeQueue(), &traceCollector{}, &auditCollector{}
	controller, err := NewController(context.Background(), config, queue, traces, audit)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		closeCtx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = controller.Close(closeCtx)
	})
	ctx := testContext(t)
	if config.Enabled {
		eventually(t, func() bool { status, _ := controller.Status(ctx); return status.ListenerReady })
	}
	return controller, queue, traces, audit
}

func mustArm(t *testing.T, controller *Controller, ctx context.Context) {
	t.Helper()
	if _, err := controller.Arm(ctx, validArm()); err != nil {
		t.Fatal(err)
	}
}

func waitPending(t *testing.T, controller *Controller, ctx context.Context, count int) []Decision {
	t.Helper()
	var result []Decision
	eventually(t, func() bool { result, _ = controller.Pending(ctx); return len(result) == count })
	return result
}

func testContext(t *testing.T) context.Context {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	t.Cleanup(cancel)
	return ctx
}

func eventually(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("condition was not met")
}

type traceCollector struct {
	mu     sync.Mutex
	events []debugtrace.Event
}

func (collector *traceCollector) TryEmit(event debugtrace.Event) bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.events = append(collector.events, event)
	return true
}
func (*traceCollector) TryBurst(debugtrace.BurstInput) bool { return true }
func (collector *traceCollector) countKind(kind debugtrace.EventKind) int {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	count := 0
	for _, event := range collector.events {
		if event.Kind == kind {
			count++
		}
	}
	return count
}

type auditCollector struct {
	mu                sync.Mutex
	waiting, finished []Decision
	drops             atomic.Uint64
}

func (collector *auditCollector) TryQueued(decision Decision) bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.waiting = append(collector.waiting, decision)
	return true
}
func (collector *auditCollector) TryTerminal(decision Decision) bool {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	collector.finished = append(collector.finished, decision)
	return true
}
func (collector *auditCollector) Dropped() uint64 { return collector.drops.Load() }
func (collector *auditCollector) queued() []Decision {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return append([]Decision(nil), collector.waiting...)
}
func (collector *auditCollector) terminal() []Decision {
	collector.mu.Lock()
	defer collector.mu.Unlock()
	return append([]Decision(nil), collector.finished...)
}
