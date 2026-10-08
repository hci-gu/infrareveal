package labgate

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"myapp/debugtrace"
	"myapp/netmeta"
)

type commandKind uint8

const (
	commandStatus commandKind = iota
	commandPending
	commandArm
	commandPause
	commandResume
	commandDrain
	commandDisarm
	commandDecide
	commandApproveAll
	commandAcceptNext
	commandShutdown
)

type controllerCommand struct {
	kind     commandKind
	arm      ArmRequest
	decision DecisionCommand
	count    int
	reply    chan controllerResponse
}

type controllerResponse struct {
	status    Status
	pending   []Decision
	decision  DecisionResult
	decisions []DecisionResult
	err       error
}

type cachedVerdict struct {
	Verdict   Verdict
	ExpiresAt time.Time
}

type activeGateIdentity struct {
	sessionID string
	mode      Mode
}

type Controller struct {
	config Config
	queue  PacketQueue
	rules  RuleManager
	trace  debugtrace.Sink
	audit  AuditSink

	ctx             context.Context
	cancel          context.CancelFunc
	commands        chan controllerCommand
	arrivals        chan QueuedPacket
	queueInfo       chan error
	done            chan struct{}
	queueDone       chan struct{}
	closeDone       chan struct{}
	closeOnce       sync.Once
	closeErr        error
	shutdownErr     error
	intakeMu        sync.RWMutex
	stopping        bool
	idCounter       atomic.Uint64
	ingressBypasses atomic.Uint64
	activeGate      atomic.Pointer[activeGateIdentity]
}

type controllerState struct {
	state     State
	mode      Mode
	sessionID string
	clients   map[netip.Addr]struct{}
	strict    *netmeta.FlowTuple
	paused    bool
	listener  bool
	lastError string

	pendingByDecisionID map[string]*Decision
	decisionByFlowKey   map[string]string
	packetToDecision    map[uint32]string
	decisionCache       map[string]cachedVerdict
	terminalByID        map[string]Decision
	terminalOrder       []string

	overflowBypasses uint64
	watchdogReleases uint64
	verdictErrors    uint64
	strictAutoAccept int
	strictTerminated bool
}

func NewController(parent context.Context, config Config, queue PacketQueue, rules RuleManager, trace debugtrace.Sink, audit AuditSink) (*Controller, error) {
	config = config.withDefaults()
	if err := config.Validate(); err != nil {
		return nil, err
	}
	if trace == nil {
		trace = debugtrace.NopSink{}
	}
	if audit == nil {
		audit = NopAuditSink{}
	}
	ctx, cancel := context.WithCancel(parent)
	controller := &Controller{
		config: config, queue: queue, rules: rules, trace: trace, audit: audit, ctx: ctx, cancel: cancel,
		commands: make(chan controllerCommand), arrivals: make(chan QueuedPacket, config.MaxHeldPackets),
		queueInfo: make(chan error, 2), done: make(chan struct{}), queueDone: make(chan struct{}), closeDone: make(chan struct{}),
	}
	go controller.run()
	if config.Enabled && queue != nil {
		go controller.runQueue()
	} else {
		close(controller.queueDone)
	}
	return controller, nil
}

func (controller *Controller) runQueue() {
	defer close(controller.queueDone)
	started := make(chan error, 1)
	go func() { started <- controller.queue.Start(controller.ctx, controller.ingest) }()
	report := func(err error) {
		select {
		case controller.queueInfo <- err:
		case <-controller.ctx.Done():
		}
	}
	var err error
	select {
	case <-controller.queue.Ready():
		report(nil)
		err = <-started
	case err = <-started:
	case <-controller.ctx.Done():
		// Close also closes the adapter before joining this worker.
		<-started
		return
	}
	if controller.ctx.Err() == nil {
		if err == nil {
			err = fmt.Errorf("packet queue stopped: %w", ErrUnavailable)
		}
		report(err)
	}
}

func (controller *Controller) ingest(packet QueuedPacket) {
	if packet.OccurredAt.IsZero() {
		packet.OccurredAt = time.Now()
	}
	controller.intakeMu.RLock()
	if controller.stopping || controller.ctx.Err() != nil {
		controller.intakeMu.RUnlock()
		err := controller.queue.SetVerdict(packet.ID, VerdictAccept)
		controller.emitBypass(packet, SourceShutdown, "gate is stopping", err)
		return
	}
	select {
	case controller.arrivals <- packet:
		controller.intakeMu.RUnlock()
	default:
		controller.intakeMu.RUnlock()
		// The user-space queue is full. Fail open immediately; recording is
		// best-effort and cannot precede the kernel verdict.
		err := controller.queue.SetVerdict(packet.ID, VerdictAccept)
		controller.ingressBypasses.Add(1)
		controller.emitBypass(packet, SourceOverflow, "controller ingress full", err)
	}
}

func (controller *Controller) Status(ctx context.Context) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandStatus})
	return result.status, result.err
}

func (controller *Controller) Pending(ctx context.Context) ([]Decision, error) {
	result := controller.request(ctx, controllerCommand{kind: commandPending})
	return result.pending, result.err
}

func (controller *Controller) Arm(ctx context.Context, request ArmRequest) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandArm, arm: request})
	return result.status, result.err
}

func (controller *Controller) Pause(ctx context.Context) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandPause})
	return result.status, result.err
}

func (controller *Controller) Resume(ctx context.Context) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandResume})
	return result.status, result.err
}

func (controller *Controller) Drain(ctx context.Context) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandDrain})
	return result.status, result.err
}

func (controller *Controller) Disarm(ctx context.Context) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandDisarm})
	return result.status, result.err
}

func (controller *Controller) Decide(ctx context.Context, command DecisionCommand) (DecisionResult, error) {
	result := controller.request(ctx, controllerCommand{kind: commandDecide, decision: command})
	return result.decision, result.err
}

func (controller *Controller) ApproveAll(ctx context.Context, actor, reason string) ([]DecisionResult, error) {
	result := controller.request(ctx, controllerCommand{kind: commandApproveAll, decision: DecisionCommand{Actor: actor, Reason: reason}})
	return result.decisions, result.err
}

func (controller *Controller) AcceptNext(ctx context.Context, count int, actor string) (Status, error) {
	result := controller.request(ctx, controllerCommand{kind: commandAcceptNext, count: count, decision: DecisionCommand{Actor: actor}})
	return result.status, result.err
}

func (controller *Controller) Close(ctx context.Context) error {
	controller.closeOnce.Do(func() {
		controller.stopIntake()
		go controller.close()
	})
	select {
	case <-controller.closeDone:
		return controller.closeErr
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (controller *Controller) close() {
	defer close(controller.closeDone)
	// A caller timeout only limits its wait. Keep the adapter and audit sink
	// available until the actor has drained its accepted packets and rules.
	controller.request(context.Background(), controllerCommand{kind: commandShutdown})
	controller.cancel()
	<-controller.done
	controller.closeErr = controller.shutdownErr
	if controller.queue != nil {
		controller.closeErr = errors.Join(controller.closeErr, controller.queue.Close())
	}
	<-controller.queueDone
}

func (controller *Controller) request(ctx context.Context, command controllerCommand) controllerResponse {
	command.reply = make(chan controllerResponse, 1)
	select {
	case controller.commands <- command:
	case <-ctx.Done():
		return controllerResponse{err: ctx.Err()}
	case <-controller.done:
		return controllerResponse{err: ErrUnavailable}
	}
	select {
	case response := <-command.reply:
		return response
	case <-ctx.Done():
		return controllerResponse{err: ctx.Err()}
	case <-controller.done:
		// Shutdown closes done immediately after placing the final response.
		// Prefer that response if both channels became ready together.
		select {
		case response := <-command.reply:
			return response
		default:
			return controllerResponse{err: ErrUnavailable}
		}
	}
}

func (controller *Controller) run() {
	defer close(controller.done)
	state := controllerState{
		state: StateOff, clients: make(map[netip.Addr]struct{}),
		pendingByDecisionID: make(map[string]*Decision), decisionByFlowKey: make(map[string]string),
		packetToDecision: make(map[uint32]string), decisionCache: make(map[string]cachedVerdict),
		terminalByID: make(map[string]Decision),
	}
	watchdogs := time.NewTicker(25 * time.Millisecond)
	defer watchdogs.Stop()
	for {
		select {
		case packet := <-controller.arrivals:
			controller.handlePacket(&state, packet)
		case queueErr := <-controller.queueInfo:
			if queueErr == nil {
				state.listener = true
			} else {
				state.listener = false
				controller.degrade(&state, queueErr)
			}
		case now := <-watchdogs.C:
			controller.expire(&state, now)
		case command := <-controller.commands:
			response, stop := controller.handleCommand(&state, command)
			command.reply <- response
			if stop {
				return
			}
		case <-controller.ctx.Done():
			controller.shutdownErr = controller.shutdown(&state)
			return
		}
	}
}

func (controller *Controller) handleCommand(state *controllerState, command controllerCommand) (controllerResponse, bool) {
	switch command.kind {
	case commandStatus:
		return controllerResponse{status: controller.status(state)}, false
	case commandPending:
		return controllerResponse{pending: pendingSnapshot(state)}, false
	case commandArm:
		err := controller.arm(state, command.arm)
		return controllerResponse{status: controller.status(state), err: err}, false
	case commandPause:
		if state.state != StateActive {
			return controllerResponse{status: controller.status(state), err: ErrInvalidTransition}, false
		}
		state.paused, state.state = true, StatePaused
		return controllerResponse{status: controller.status(state)}, false
	case commandResume:
		if state.state != StatePaused {
			return controllerResponse{status: controller.status(state), err: ErrInvalidTransition}, false
		}
		state.paused, state.state = false, StateActive
		return controllerResponse{status: controller.status(state)}, false
	case commandDrain:
		if state.state != StateActive && state.state != StatePaused && state.state != StateDegraded {
			return controllerResponse{status: controller.status(state), err: ErrInvalidTransition}, false
		}
		state.state = StateDraining
		controller.drainArrivals(state)
		controller.releaseAll(state, DecisionDrained, SourceSystem, "operator drain")
		state.paused, state.state = true, StatePaused
		return controllerResponse{status: controller.status(state)}, false
	case commandDisarm:
		if state.state == StateOff {
			return controllerResponse{status: controller.status(state)}, false
		}
		state.state = StateDraining
		controller.drainArrivals(state)
		controller.releaseAll(state, DecisionDrained, SourceSystem, "disarm")
		if err := controller.clearRuleClients(); err != nil {
			state.lastError = err.Error()
			// Keep the selection visible and retryable. Packets that still hit a
			// stale rule are accepted immediately while the controller is degraded.
			state.state, state.paused = StateDegraded, true
			state.strictAutoAccept, state.strictTerminated = 0, false
			clear(state.decisionCache)
			return controllerResponse{status: controller.status(state), err: err}, false
		}
		controller.clearArmState(state)
		return controllerResponse{status: controller.status(state)}, false
	case commandDecide:
		result, err := controller.decide(state, command.decision)
		return controllerResponse{status: controller.status(state), decision: result, err: err}, false
	case commandApproveAll:
		results := make([]DecisionResult, 0, len(state.pendingByDecisionID))
		for _, decision := range pendingSnapshot(state) {
			result, err := controller.decide(state, DecisionCommand{DecisionID: decision.ID, Verdict: VerdictAccept, Actor: command.decision.Actor, Reason: command.decision.Reason})
			if err != nil {
				return controllerResponse{decisions: results, status: controller.status(state), err: err}, false
			}
			results = append(results, result)
		}
		return controllerResponse{decisions: results, status: controller.status(state)}, false
	case commandAcceptNext:
		if state.state != StateActive || state.mode != ModeStrict || command.count < 1 || command.count > 100 {
			return controllerResponse{status: controller.status(state), err: ErrInvalidTransition}, false
		}
		state.strictAutoAccept += command.count
		for _, decision := range pendingSnapshotPointers(state) {
			if state.strictAutoAccept == 0 {
				break
			}
			state.strictAutoAccept--
			controller.applyTerminal(state, decision, DecisionApproved, VerdictAccept, SourceOperator, safeActor(command.decision.Actor), "strict accept-next", time.Now())
		}
		return controllerResponse{status: controller.status(state)}, false
	case commandShutdown:
		controller.shutdownErr = controller.shutdown(state)
		return controllerResponse{status: controller.status(state), err: controller.shutdownErr}, true
	default:
		return controllerResponse{err: ErrInvalidTransition}, false
	}
}

func (controller *Controller) shutdown(state *controllerState) error {
	controller.stopIntake()
	state.state = StateDraining
	controller.drainArrivals(state)
	controller.releaseAll(state, DecisionDrained, SourceShutdown, "shutdown")
	err := controller.clearRuleClients()
	if controller.rules != nil {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		err = errors.Join(err, controller.rules.Cleanup(cleanupCtx))
		cancel()
	}
	if err != nil {
		state.lastError = err.Error()
	}
	controller.clearArmState(state)
	return err
}

func (controller *Controller) stopIntake() {
	// Once this returns, earlier callbacks have either queued their packet or
	// accepted it. Later callbacks accept directly instead of racing the drain.
	controller.intakeMu.Lock()
	controller.stopping = true
	controller.intakeMu.Unlock()
}

func (controller *Controller) drainArrivals(state *controllerState) {
	for {
		select {
		case packet := <-controller.arrivals:
			controller.handlePacket(state, packet)
		default:
			return
		}
	}
}

func (controller *Controller) arm(state *controllerState, request ArmRequest) error {
	if !controller.config.Enabled {
		return ErrDisabled
	}
	if controller.queue == nil || !state.listener {
		return ErrUnavailable
	}
	if !controller.config.FailOpen {
		return errors.Join(ErrInvalidArmRequest, errors.New("fail-open must be enabled"))
	}
	if controller.config.ControlTokenFile == "" {
		return errors.Join(ErrInvalidArmRequest, errors.New("control token is not configured"))
	}
	if state.state != StateOff {
		return ErrInvalidTransition
	}
	if strings.TrimSpace(request.SessionID) == "" || len(request.Clients) == 0 || (request.Mode != ModeFlow && request.Mode != ModeStrict && request.Mode != ModeDNS) {
		return ErrInvalidArmRequest
	}
	if request.Mode == ModeStrict && (len(request.Clients) != 1 || request.Strict == nil || !request.Strict.Valid() || request.Strict.ClientPort == 0 || request.Strict.ClientIP.Unmap() != request.Clients[0].Unmap()) {
		return errors.Join(ErrInvalidArmRequest, errors.New("strict mode requires one client and one complete tuple"))
	}
	if request.Mode != ModeStrict && request.Strict != nil {
		return ErrInvalidArmRequest
	}
	clients := make(map[netip.Addr]struct{}, len(request.Clients))
	for _, client := range request.Clients {
		client = client.Unmap()
		if !client.IsValid() || !client.Is4() {
			return ErrInvalidArmRequest
		}
		clients[client] = struct{}{}
	}
	state.state = StateArming
	state.sessionID, state.mode, state.clients, state.strict = strings.TrimSpace(request.SessionID), request.Mode, clients, request.Strict
	state.paused, state.lastError = false, ""
	controller.activeGate.Store(&activeGateIdentity{sessionID: state.sessionID, mode: state.mode})
	if controller.rules != nil {
		selected := make([]netip.Addr, 0, len(clients))
		for client := range clients {
			selected = append(selected, client)
		}
		sort.Slice(selected, func(i, j int) bool { return selected[i].Less(selected[j]) })
		ruleCtx, cancel := context.WithTimeout(controller.ctx, 2*time.Second)
		err := controller.rules.Activate(ruleCtx, RuleSelection{Mode: request.Mode, Clients: selected, Strict: request.Strict})
		cancel()
		if err != nil {
			cleanupErr := controller.clearRuleClients()
			combined := errors.Join(err, cleanupErr)
			state.lastError = combined.Error()
			if cleanupErr != nil {
				state.state, state.paused = StateDegraded, true
				return errors.Join(ErrUnavailable, combined)
			}
			controller.clearArmState(state)
			return errors.Join(ErrUnavailable, combined)
		}
	}
	state.state = StateActive
	return nil
}

func (controller *Controller) clearRuleClients() error {
	if controller.rules == nil {
		return nil
	}
	ruleCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	return controller.rules.ClearClients(ruleCtx)
}

func (controller *Controller) clearArmState(state *controllerState) {
	controller.activeGate.Store(nil)
	state.state, state.mode, state.sessionID, state.paused = StateOff, "", "", false
	state.clients = make(map[netip.Addr]struct{})
	state.strict = nil
	state.strictAutoAccept = 0
	state.strictTerminated = false
	clear(state.decisionCache)
}

func (controller *Controller) handlePacket(state *controllerState, packet QueuedPacket) {
	if controller.queue == nil {
		return
	}
	if packet.ID == 0 || !packet.Tuple.Valid() || (state.mode != ModeStrict && packet.Direction != netmeta.ClientToRemote) {
		controller.acceptBypass(state, packet, SourceSystem, "invalid or unsupported packet")
		return
	}
	if packet.QueueMode != "" && packet.QueueMode != state.mode {
		controller.acceptBypass(state, packet, SourceSystem, "packet belongs to an inactive gate mode")
		return
	}
	if _, duplicate := state.packetToDecision[packet.ID]; duplicate {
		return
	}
	if state.state != StateActive || state.paused {
		controller.acceptBypass(state, packet, SourceSystem, "gate intake inactive")
		return
	}
	if _, selected := state.clients[packet.Tuple.ClientIP.Unmap()]; !selected {
		controller.acceptBypass(state, packet, SourceSystem, "client not selected")
		return
	}
	if state.mode == ModeStrict {
		controller.handleStrictPacket(state, packet)
		return
	}
	flowKey := packet.Tuple.Key()
	now := time.Now()
	if cached, ok := state.decisionCache[flowKey]; ok {
		if now.Before(cached.ExpiresAt) {
			if err := controller.queue.SetVerdict(packet.ID, cached.Verdict); err != nil {
				controller.degrade(state, err)
			}
			return
		}
		delete(state.decisionCache, flowKey)
	}
	if decisionID, ok := state.decisionByFlowKey[flowKey]; ok {
		if len(state.packetToDecision) >= controller.config.MaxHeldPackets {
			controller.acceptBypass(state, packet, SourceOverflow, "held packet cap reached")
			return
		}
		decision := state.pendingByDecisionID[decisionID]
		decision.packetIDs = append(decision.packetIDs, packet.ID)
		decision.PacketCount++
		decision.TCPFlags |= packet.TCPFlags
		state.packetToDecision[packet.ID] = decisionID
		return
	}
	if packet.Tuple.Protocol == "tcp" && packet.TCPFlags&0x02 == 0 {
		controller.acceptBypass(state, packet, SourceSystem, "unseen TCP packet is not SYN")
		return
	}
	if len(state.pendingByDecisionID) >= controller.config.MaxPendingFlows || len(state.packetToDecision) >= controller.config.MaxHeldPackets {
		controller.acceptBypass(state, packet, SourceOverflow, "gate capacity reached")
		return
	}
	controller.queueDecision(state, packet)
}

func (controller *Controller) handleStrictPacket(state *controllerState, packet QueuedPacket) {
	if state.strict == nil || packet.Tuple.Key() != state.strict.Key() {
		controller.acceptBypass(state, packet, SourceSystem, "packet does not match the strict tuple")
		return
	}
	if len(state.pendingByDecisionID) >= controller.config.MaxPendingFlows || len(state.packetToDecision) >= controller.config.MaxHeldPackets {
		controller.acceptBypass(state, packet, SourceOverflow, "strict packet capacity reached")
		return
	}
	controller.queueDecision(state, packet)
}

func (controller *Controller) queueDecision(state *controllerState, packet QueuedPacket) {
	queuedAt := packet.OccurredAt
	prefix := "gate"
	if state.mode == ModeStrict {
		prefix = "strict"
	}
	decisionID := fmt.Sprintf("%s-%d-%d", prefix, queuedAt.UnixMilli(), controller.idCounter.Add(1))
	decision := &Decision{
		ID: decisionID, SessionID: state.sessionID, FlowKey: packet.Tuple.Key(), Tuple: packet.Tuple,
		ClientIP: packet.Tuple.ClientIP.String(), ClientPort: packet.Tuple.ClientPort,
		RemoteIP: packet.Tuple.RemoteIP.String(), RemotePort: packet.Tuple.RemotePort,
		Protocol: packet.Tuple.Protocol, Mode: state.mode, Direction: packet.Direction, WireBytes: packet.WireBytes, PayloadBytes: packet.PayloadBytes, PacketCount: 1, TCPFlags: packet.TCPFlags,
		QueuedAt: queuedAt, Deadline: queuedAt.Add(controller.decisionTimeout(state.mode)), State: DecisionQueued,
		packetIDs: []uint32{packet.ID},
	}
	state.pendingByDecisionID[decisionID] = decision
	if state.mode != ModeStrict {
		state.decisionByFlowKey[decision.FlowKey] = decisionID
	}
	state.packetToDecision[packet.ID] = decisionID
	if !controller.audit.TryQueued(decision.clone()) {
		state.lastError = "gate audit queue full"
	}
	controller.emitDecision(*decision, "queued")
	if state.mode == ModeStrict && state.strictAutoAccept > 0 {
		state.strictAutoAccept--
		controller.applyTerminal(state, decision, DecisionApproved, VerdictAccept, SourceOperator, "operator", "strict accept-next", time.Now())
	}
}

func (controller *Controller) decisionTimeout(mode Mode) time.Duration {
	switch mode {
	case ModeStrict:
		return controller.config.EstablishedTimeout
	case ModeDNS:
		return controller.config.DNSTimeout
	default:
		return controller.config.FlowTimeout
	}
}

func (controller *Controller) decide(state *controllerState, command DecisionCommand) (DecisionResult, error) {
	if command.Verdict != VerdictAccept && command.Verdict != VerdictDrop {
		return DecisionResult{}, ErrInvalidTransition
	}
	if terminal, ok := state.terminalByID[command.DecisionID]; ok {
		return DecisionResult{Decision: terminal.clone(), AlreadyTerminal: true}, nil
	}
	decision, ok := state.pendingByDecisionID[command.DecisionID]
	if !ok {
		return DecisionResult{}, ErrDecisionNotFound
	}
	terminalState := DecisionApproved
	if command.Verdict == VerdictDrop {
		terminalState = DecisionRejected
	}
	finished := controller.applyTerminal(state, decision, terminalState, command.Verdict, SourceOperator, command.Actor, command.Reason, time.Now())
	return DecisionResult{Decision: finished.clone()}, nil
}

func (controller *Controller) expire(state *controllerState, now time.Time) {
	for _, decision := range pendingSnapshotPointers(state) {
		if decision.State == DecisionQueued && !now.Before(decision.Deadline) {
			controller.applyTerminal(state, decision, DecisionExpired, VerdictAccept, SourceWatchdog, "", "safety timeout", now)
			state.watchdogReleases++
		}
	}
	for key, cached := range state.decisionCache {
		if !now.Before(cached.ExpiresAt) {
			delete(state.decisionCache, key)
		}
	}
}

func (controller *Controller) releaseAll(state *controllerState, terminalState DecisionState, source VerdictSource, reason string) {
	for _, decision := range pendingSnapshotPointers(state) {
		controller.applyTerminal(state, decision, terminalState, VerdictAccept, source, "", reason, time.Now())
	}
}

func (controller *Controller) applyTerminal(state *controllerState, decision *Decision, terminalState DecisionState, verdict Verdict, source VerdictSource, actor, reason string, decidedAt time.Time) Decision {
	// A failed verdict can drain the remaining decisions during an outer
	// watchdog/drain pass. Do not apply a second terminal transition to them.
	if _, pending := state.pendingByDecisionID[decision.ID]; !pending {
		return *decision
	}
	_, verdictErr := controller.applyPacketVerdicts(state, decision, verdict)
	// Flow admission caches a verdict for the lifetime of the admitted flow.
	// DNS is datagram/query-oriented and strict mode is packet-oriented, so a
	// terminal decision must not silently approve the next item on that tuple.
	if decision.Mode == ModeFlow {
		state.decisionCache[decision.FlowKey] = cachedVerdict{Verdict: verdict, ExpiresAt: decidedAt.Add(controller.config.DecisionCache)}
	}
	controller.recordTerminal(state, decision, terminalState, verdict, source, actor, reason, decidedAt)
	if verdictErr != nil {
		controller.degrade(state, verdictErr)
	}
	if state.mode == ModeStrict && decision.Protocol == "tcp" && decision.TCPFlags&0x05 != 0 {
		state.strictTerminated = true
	}
	if state.mode == ModeStrict && state.strictTerminated && len(state.pendingByDecisionID) == 0 {
		if err := controller.clearRuleClients(); err != nil {
			state.lastError = err.Error()
			state.state, state.paused = StateDegraded, true
			state.strictAutoAccept, state.strictTerminated = 0, false
			clear(state.decisionCache)
		} else {
			controller.clearArmState(state)
		}
	}
	return *decision
}

// Kernel verdicts always precede terminal persistence and trace work.
func (controller *Controller) applyPacketVerdicts(state *controllerState, decision *Decision, verdict Verdict) (int, error) {
	var result error
	errorsCount := 0
	for _, packetID := range decision.packetIDs {
		if err := controller.queue.SetVerdict(packetID, verdict); err != nil {
			result = errors.Join(result, err)
			errorsCount++
		}
		delete(state.packetToDecision, packetID)
	}
	return errorsCount, result
}

func (controller *Controller) recordTerminal(state *controllerState, decision *Decision, terminalState DecisionState, verdict Verdict, source VerdictSource, actor, reason string, decidedAt time.Time) {
	delete(state.pendingByDecisionID, decision.ID)
	delete(state.decisionByFlowKey, decision.FlowKey)
	decision.State, decision.Verdict, decision.Source = terminalState, verdict, source
	decision.Actor, decision.Reason, decision.DecidedAt = actor, reason, decidedAt
	decision.WaitMS = max(0, decidedAt.Sub(decision.QueuedAt).Milliseconds())
	controller.rememberTerminal(state, *decision)
	controller.emitDecision(*decision, "verdict")
	if !controller.audit.TryTerminal(decision.clone()) {
		state.lastError = "gate audit queue full"
	}
}

func (controller *Controller) rememberTerminal(state *controllerState, decision Decision) {
	state.terminalByID[decision.ID] = decision.clone()
	state.terminalOrder = append(state.terminalOrder, decision.ID)
	if len(state.terminalOrder) > 2048 {
		delete(state.terminalByID, state.terminalOrder[0])
		state.terminalOrder = state.terminalOrder[1:]
	}
}

func (controller *Controller) acceptBypass(state *controllerState, packet QueuedPacket, source VerdictSource, reason string) {
	err := controller.queue.SetVerdict(packet.ID, VerdictAccept)
	if source == SourceOverflow {
		state.overflowBypasses++
	}
	if !controller.recordBypass(state.sessionID, state.mode, packet, source, reason, err) {
		state.lastError = "gate audit queue full"
	}
	if err != nil {
		controller.degrade(state, err)
	}
}

func (controller *Controller) emitBypass(packet QueuedPacket, source VerdictSource, reason string, verdictErr error) {
	identity := controller.activeGate.Load()
	if identity == nil {
		controller.recordBypass("", "", packet, source, reason, verdictErr)
		return
	}
	mode := packet.QueueMode
	if mode == "" {
		mode = identity.mode
	}
	controller.recordBypass(identity.sessionID, mode, packet, source, reason, verdictErr)
}

func (controller *Controller) recordBypass(sessionID string, mode Mode, packet QueuedPacket, source VerdictSource, reason string, verdictErr error) bool {
	if sessionID == "" || source != SourceOverflow {
		controller.emitBypassForSession(sessionID, packet, source, verdictErr, "")
		return true
	}
	decidedAt := time.Now()
	if verdictErr != nil {
		reason = fmt.Sprintf("%s; verdict error: %v", reason, verdictErr)
	}
	decision := Decision{
		ID:        fmt.Sprintf("bypass-%d-%d", packet.OccurredAt.UnixMilli(), controller.idCounter.Add(1)),
		SessionID: sessionID, FlowKey: packet.Tuple.Key(), Tuple: packet.Tuple,
		ClientIP: packet.Tuple.ClientIP.String(), ClientPort: packet.Tuple.ClientPort,
		RemoteIP: packet.Tuple.RemoteIP.String(), RemotePort: packet.Tuple.RemotePort,
		Protocol: packet.Tuple.Protocol, Mode: mode, Direction: packet.Direction,
		WireBytes: packet.WireBytes, PayloadBytes: packet.PayloadBytes, PacketCount: 1, TCPFlags: packet.TCPFlags,
		QueuedAt: packet.OccurredAt, Deadline: decidedAt, State: DecisionBypassed,
		Verdict: VerdictAccept, Source: source, Reason: truncateAuditReason(reason), DecidedAt: decidedAt,
		WaitMS: max(0, decidedAt.Sub(packet.OccurredAt).Milliseconds()),
	}
	controller.emitBypassForSession(sessionID, packet, source, verdictErr, decision.ID)
	return controller.audit.TryTerminal(decision)
}

func truncateAuditReason(reason string) string {
	const maxAuditReasonLength = 500
	if len(reason) <= maxAuditReasonLength {
		return reason
	}
	return reason[:maxAuditReasonLength]
}

func (controller *Controller) emitBypassForSession(sessionID string, packet QueuedPacket, source VerdictSource, verdictErr error, decisionID string) {
	clientPort, remotePort := packet.Tuple.ClientPort, packet.Tuple.RemotePort
	wireBytes, payloadBytes, packetCount := uint64(packet.WireBytes), uint64(packet.PayloadBytes), uint64(1)
	verdict := string(VerdictAccept)
	if verdictErr != nil {
		verdict = "error"
	}
	id, parentID := fmt.Sprintf("gate-bypass:%d:%d", packet.ID, packet.OccurredAt.UnixMilli()), ""
	if decisionID != "" {
		id, parentID = fmt.Sprintf("gate:%s:verdict", decisionID), fmt.Sprintf("gate:%s:queued", decisionID)
	}
	controller.trace.TryEmit(debugtrace.Event{
		ID: id, ParentID: parentID,
		SessionID: fallbackSession(sessionID), TraceID: fallbackTraceID(packet.Tuple.Key()), Kind: debugtrace.KindGate,
		Stage: debugtrace.StageGateQueue, Direction: traceDirection(packet.Direction),
		OccurredAtMs: packet.OccurredAt.UnixMilli(), Timing: debugtrace.TimingObserved,
		Summary: debugtrace.Summary{Protocol: packet.Tuple.Protocol, ClientIP: packet.Tuple.ClientIP.String(), ClientPort: &clientPort,
			RemoteIP: packet.Tuple.RemoteIP.String(), RemotePort: &remotePort, FlowKey: packet.Tuple.Key(), WireBytes: &wireBytes,
			PayloadBytes: &payloadBytes, PacketCount: &packetCount, TCPFlags: &packet.TCPFlags, Verdict: verdict, VerdictSource: string(source)},
	})
}

func (controller *Controller) emitDecision(decision Decision, phase string) {
	clientPort, remotePort := decision.ClientPort, decision.RemotePort
	packetCount := uint64(decision.PacketCount)
	parentID := ""
	if phase == "verdict" {
		parentID = fmt.Sprintf("gate:%s:queued", decision.ID)
	}
	controller.trace.TryEmit(debugtrace.Event{
		ID: fmt.Sprintf("gate:%s:%s", decision.ID, phase), ParentID: parentID, SessionID: decision.SessionID,
		TraceID: decision.FlowKey, Kind: debugtrace.KindGate, Stage: debugtrace.StageGateQueue,
		Direction: traceDirection(decision.Direction), OccurredAtMs: eventTime(decision, phase).UnixMilli(), Timing: debugtrace.TimingObserved,
		Summary: debugtrace.Summary{Protocol: decision.Protocol, ClientIP: decision.ClientIP, ClientPort: &clientPort,
			RemoteIP: decision.RemoteIP, RemotePort: &remotePort, FlowKey: decision.FlowKey, PacketCount: &packetCount,
			TCPFlags: &decision.TCPFlags, Verdict: string(decision.Verdict), VerdictSource: string(decision.Source)},
	})
}

func eventTime(decision Decision, phase string) time.Time {
	if phase == "verdict" && !decision.DecidedAt.IsZero() {
		return decision.DecidedAt
	}
	return decision.QueuedAt
}

func traceDirection(direction netmeta.Direction) debugtrace.Direction {
	if direction == netmeta.RemoteToClient {
		return debugtrace.RemoteToClient
	}
	return debugtrace.ClientToRemote
}

func (controller *Controller) degrade(state *controllerState, err error) {
	if err == nil {
		return
	}
	state.verdictErrors++
	state.lastError = err.Error()
	state.state, state.paused = StateDegraded, true
	// Try remaining releases once. SetVerdict errors are retained in status,
	// while adapter closure/kernel fail-open is the final safety boundary.
	for _, decision := range pendingSnapshotPointers(state) {
		controller.applyTerminalNoDegrade(state, decision, DecisionDrained, SourceSystem, "queue failure", time.Now())
	}
	captureComplete := false
	controller.trace.TryEmit(debugtrace.Event{
		ID: fmt.Sprintf("gate-health:%d", time.Now().UnixNano()), SessionID: fallbackSession(state.sessionID),
		TraceID: "lab-gate", Kind: debugtrace.KindHealth, Stage: debugtrace.StageHealth,
		OccurredAtMs: time.Now().UnixMilli(), Timing: debugtrace.TimingObserved,
		Summary: debugtrace.Summary{Verdict: "degraded", VerdictSource: string(SourceSystem), CaptureComplete: &captureComplete},
	})
}

func (controller *Controller) applyTerminalNoDegrade(state *controllerState, decision *Decision, terminalState DecisionState, source VerdictSource, reason string, decidedAt time.Time) {
	errorsCount, _ := controller.applyPacketVerdicts(state, decision, VerdictAccept)
	state.verdictErrors += uint64(errorsCount)
	controller.recordTerminal(state, decision, terminalState, VerdictAccept, source, "", reason, decidedAt)
}

func (controller *Controller) status(state *controllerState) Status {
	clients := make([]string, 0, len(state.clients))
	for client := range state.clients {
		clients = append(clients, client.String())
	}
	sort.Strings(clients)
	oldestWait := int64(0)
	if pending := pendingSnapshotPointers(state); len(pending) > 0 {
		oldestWait = max(0, time.Since(pending[0].QueuedAt).Milliseconds())
	}
	queueStats := QueueStats{}
	if controller.queue != nil {
		queueStats = controller.queue.Stats()
	}
	return Status{
		Enabled: controller.config.Enabled, Supported: controller.queue != nil, ListenerReady: state.listener,
		RulesReady: controller.rules != nil && controller.rules.Ready(), Armed: state.state != StateOff, Paused: state.paused,
		State: state.state, Mode: state.mode, SessionID: state.sessionID, Clients: clients,
		PendingFlows: len(state.pendingByDecisionID), HeldPackets: len(state.packetToDecision), OldestWaitMS: oldestWait,
		OverflowBypasses: state.overflowBypasses + controller.ingressBypasses.Load(), WatchdogReleases: state.watchdogReleases,
		VerdictErrors: state.verdictErrors, AuditDrops: controller.audit.Dropped(), Queue: queueStats, ParseBypassCount: queueStats.ParseBypass, LastError: state.lastError,
		FailOpen: controller.config.FailOpen, FlowTimeoutMS: controller.config.FlowTimeout.Milliseconds(),
		EstablishedTimeoutMS: controller.config.EstablishedTimeout.Milliseconds(), DNSTimeoutMS: controller.config.DNSTimeout.Milliseconds(),
		MaxPendingFlows: controller.config.MaxPendingFlows, MaxHeldPackets: controller.config.MaxHeldPackets,
		StrictAutoAccept: state.strictAutoAccept,
		KernelSettings:   cloneStringMap(controller.config.KernelSettings),
	}
}

func cloneStringMap(source map[string]string) map[string]string {
	result := make(map[string]string, len(source))
	for key, value := range source {
		result[key] = value
	}
	return result
}

func pendingSnapshot(state *controllerState) []Decision {
	pointers := pendingSnapshotPointers(state)
	result := make([]Decision, 0, len(pointers))
	for _, decision := range pointers {
		result = append(result, decision.clone())
	}
	return result
}

func pendingSnapshotPointers(state *controllerState) []*Decision {
	result := make([]*Decision, 0, len(state.pendingByDecisionID))
	for _, decision := range state.pendingByDecisionID {
		result = append(result, decision)
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].QueuedAt.Equal(result[j].QueuedAt) {
			return result[i].ID < result[j].ID
		}
		return result[i].QueuedAt.Before(result[j].QueuedAt)
	})
	return result
}

func fallbackSession(sessionID string) string {
	if sessionID == "" {
		return "unassigned"
	}
	return sessionID
}

func fallbackTraceID(flowKey string) string {
	if flowKey == "" {
		return "unparsed-packet"
	}
	return flowKey
}
