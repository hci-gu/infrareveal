package labgate

import (
	"context"
	"errors"
	"net/netip"
	"time"

	"myapp/netmeta"
)

var (
	ErrDisabled          = errors.New("lab gate is disabled")
	ErrUnavailable       = errors.New("lab gate is unavailable")
	ErrInvalidTransition = errors.New("invalid lab gate state transition")
	ErrInvalidArmRequest = errors.New("invalid lab gate arm request")
	ErrDecisionNotFound  = errors.New("gate decision not found")
)

type State string

const (
	StateOff      State = "off"
	StateArming   State = "arming"
	StateActive   State = "active"
	StatePaused   State = "paused"
	StateDraining State = "draining"
	StateDegraded State = "degraded"
	StateError    State = "error"
)

type Mode string

const (
	ModeFlow   Mode = "flow"
	ModeStrict Mode = "strict"
	ModeDNS    Mode = "dns"
)

type Verdict string

const (
	VerdictAccept Verdict = "accept"
	VerdictDrop   Verdict = "drop"
)

type VerdictSource string

const (
	SourceOperator VerdictSource = "operator"
	SourceWatchdog VerdictSource = "watchdog"
	SourceOverflow VerdictSource = "overflow"
	SourceShutdown VerdictSource = "shutdown"
	SourceSystem   VerdictSource = "system"
)

type QueuedPacket struct {
	ID           uint32
	QueueMode    Mode
	Tuple        netmeta.FlowTuple
	Direction    netmeta.Direction
	WireBytes    uint32
	PayloadBytes uint32
	TCPFlags     uint16
	OccurredAt   time.Time
}

type QueueStats struct {
	QueueDepth  uint64 `json:"queueDepth"`
	KernelDrops uint64 `json:"kernelDrops"`
	UserDrops   uint64 `json:"userDrops"`
	ParseBypass uint64 `json:"parseBypass"`
}

type PacketQueue interface {
	Start(context.Context, func(QueuedPacket)) error
	SetVerdict(packetID uint32, verdict Verdict) error
	Stats() QueueStats
	Close() error
}

type ReadyPacketQueue interface {
	PacketQueue
	Ready() <-chan struct{}
}

type DecisionState string

const (
	DecisionQueued   DecisionState = "queued"
	DecisionApproved DecisionState = "approved"
	DecisionRejected DecisionState = "rejected"
	DecisionExpired  DecisionState = "expired"
	DecisionBypassed DecisionState = "bypassed"
	DecisionDrained  DecisionState = "drained"
)

type Decision struct {
	ID           string            `json:"id"`
	SessionID    string            `json:"sessionId"`
	FlowKey      string            `json:"flowKey"`
	Tuple        netmeta.FlowTuple `json:"-"`
	ClientIP     string            `json:"clientIp"`
	ClientPort   uint16            `json:"clientPort"`
	RemoteIP     string            `json:"remoteIp"`
	RemotePort   uint16            `json:"remotePort"`
	Protocol     string            `json:"protocol"`
	Mode         Mode              `json:"mode"`
	Direction    netmeta.Direction `json:"direction"`
	WireBytes    uint32            `json:"wireBytes"`
	PayloadBytes uint32            `json:"payloadBytes"`
	PacketCount  int               `json:"packetCount"`
	TCPFlags     uint16            `json:"tcpFlags"`
	QueuedAt     time.Time         `json:"queuedAt"`
	Deadline     time.Time         `json:"deadline"`
	State        DecisionState     `json:"state"`
	Verdict      Verdict           `json:"verdict,omitempty"`
	Source       VerdictSource     `json:"verdictSource,omitempty"`
	Actor        string            `json:"actor,omitempty"`
	Reason       string            `json:"reason,omitempty"`
	DecidedAt    time.Time         `json:"decidedAt,omitempty"`
	WaitMS       int64             `json:"waitMs"`
	packetIDs    []uint32
}

func (decision Decision) clone() Decision {
	decision.packetIDs = nil
	return decision
}

type ArmRequest struct {
	SessionID string
	Mode      Mode
	Clients   []netip.Addr
	Strict    *netmeta.FlowTuple
}

type DecisionCommand struct {
	DecisionID string
	Verdict    Verdict
	Actor      string
	Reason     string
}

type Status struct {
	Enabled              bool              `json:"enabled"`
	Supported            bool              `json:"supported"`
	ListenerReady        bool              `json:"listenerReady"`
	RulesReady           bool              `json:"rulesReady"`
	Armed                bool              `json:"armed"`
	Paused               bool              `json:"paused"`
	State                State             `json:"state"`
	Mode                 Mode              `json:"mode,omitempty"`
	SessionID            string            `json:"sessionId,omitempty"`
	Clients              []string          `json:"clientIps"`
	PendingFlows         int               `json:"pendingFlows"`
	HeldPackets          int               `json:"heldPackets"`
	OldestWaitMS         int64             `json:"oldestWaitMs"`
	OverflowBypasses     uint64            `json:"overflowCount"`
	WatchdogReleases     uint64            `json:"watchdogReleases"`
	VerdictErrors        uint64            `json:"verdictErrors"`
	AuditDrops           uint64            `json:"auditDrops"`
	Queue                QueueStats        `json:"queue"`
	ParseBypassCount     uint64            `json:"parseBypassCount"`
	FailOpen             bool              `json:"failOpen"`
	FlowTimeoutMS        int64             `json:"flowTimeoutMs"`
	EstablishedTimeoutMS int64             `json:"establishedTimeoutMs"`
	DNSTimeoutMS         int64             `json:"dnsTimeoutMs"`
	MaxPendingFlows      int               `json:"maxPendingFlows"`
	MaxHeldPackets       int               `json:"maxHeldPackets"`
	LastError            string            `json:"lastError,omitempty"`
	StrictAutoAccept     int               `json:"strictAutoAccept"`
	KernelSettings       map[string]string `json:"kernelSettings"`
}

type DecisionResult struct {
	Decision        Decision `json:"decision"`
	AlreadyTerminal bool     `json:"alreadyTerminal"`
}

type AuditSink interface {
	TryQueued(Decision) bool
	TryTerminal(Decision) bool
	Dropped() uint64
}

type NopAuditSink struct{}

func (NopAuditSink) TryQueued(Decision) bool   { return true }
func (NopAuditSink) TryTerminal(Decision) bool { return true }
func (NopAuditSink) Dropped() uint64           { return 0 }
