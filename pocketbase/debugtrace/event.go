// Package debugtrace defines the bounded, payload-free event vocabulary used
// by the optional proxy-lab visualization. It has no PocketBase or observer
// dependencies so producers cannot accidentally couple forwarding to the UI.
package debugtrace

import (
	"errors"
	"fmt"
	"strings"
)

const ProtocolVersion = 1

type EventKind string

const (
	KindDNS         EventKind = "dns"
	KindFlow        EventKind = "flow"
	KindBurst       EventKind = "burst"
	KindAttribution EventKind = "attribution"
	KindDestination EventKind = "destination"
	KindRoute       EventKind = "route"
	KindGate        EventKind = "gate"
	KindHealth      EventKind = "health"
)

type Stage string

const (
	StageClient         Stage = "client"
	StageGatewayIngress Stage = "gateway_ingress"
	StageDNS            Stage = "dns"
	StageConntrack      Stage = "conntrack"
	StageHeaderCapture  Stage = "header_capture"
	StageGateQueue      Stage = "gate_queue"
	StageForward        Stage = "forward"
	StageNAT            Stage = "nat"
	StageRemote         Stage = "remote"
	StageAttribution    Stage = "attribution"
	StageDestination    Stage = "destination"
	StageRoute          Stage = "route"
	StageHealth         Stage = "health"
)

type Direction string

const (
	ClientToRemote Direction = "client_to_remote"
	RemoteToClient Direction = "remote_to_client"
)

type Timing string

const (
	TimingObserved Timing = "observed"
	TimingDerived  Timing = "derived"
)

// Summary is deliberately an explicit allowlist. Packet bytes, HTTP/TLS data,
// arbitrary labels, and user-controlled maps have no representation here.
type Summary struct {
	Protocol        string  `json:"protocol,omitempty"`
	ClientIP        string  `json:"clientIp,omitempty"`
	ClientPort      *uint16 `json:"clientPort,omitempty"`
	RemoteIP        string  `json:"remoteIp,omitempty"`
	RemotePort      *uint16 `json:"remotePort,omitempty"`
	FlowKey         string  `json:"flowKey,omitempty"`
	DNSName         string  `json:"dnsName,omitempty"`
	DNSType         string  `json:"dnsType,omitempty"`
	Hostname        string  `json:"hostname,omitempty"`
	Confidence      string  `json:"confidence,omitempty"`
	WireBytes       *uint64 `json:"wireBytes,omitempty"`
	PayloadBytes    *uint64 `json:"payloadBytes,omitempty"`
	PacketCount     *uint64 `json:"packetCount,omitempty"`
	TCPFlags        *uint16 `json:"tcpFlags,omitempty"`
	Verdict         string  `json:"verdict,omitempty"`
	VerdictSource   string  `json:"verdictSource,omitempty"`
	DroppedEvents   *uint64 `json:"droppedEvents,omitempty"`
	CaptureComplete *bool   `json:"captureComplete,omitempty"`
}

type Event struct {
	ID            string    `json:"id"`
	Sequence      uint64    `json:"sequence"`
	SessionID     string    `json:"sessionId"`
	TraceID       string    `json:"traceId"`
	ParentID      string    `json:"parentId,omitempty"`
	Kind          EventKind `json:"kind"`
	Stage         Stage     `json:"stage"`
	Direction     Direction `json:"direction,omitempty"`
	OccurredAtMs  int64     `json:"occurredAtMs"`
	ProcessedAtMs *int64    `json:"processedAtMs,omitempty"`
	Timing        Timing    `json:"timing"`
	Summary       Summary   `json:"summary"`
}

type StreamEnvelope struct {
	Version       uint8   `json:"version"`
	SessionID     string  `json:"sessionId"`
	Events        []Event `json:"events"`
	DroppedEvents uint64  `json:"droppedEvents"`
	ServerNowMs   int64   `json:"serverNowMs"`
}

var ErrInvalidEvent = errors.New("invalid debug trace event")

func (event Event) Validate() error {
	if !validRequiredString(event.ID, 256) || !validRequiredString(event.SessionID, 128) || !validRequiredString(event.TraceID, 256) {
		return fmt.Errorf("%w: missing or oversized identity", ErrInvalidEvent)
	}
	if event.ParentID != "" && !validRequiredString(event.ParentID, 256) {
		return fmt.Errorf("%w: oversized parent id", ErrInvalidEvent)
	}
	if !event.Kind.valid() || !event.Stage.valid() {
		return fmt.Errorf("%w: unknown kind or stage", ErrInvalidEvent)
	}
	if event.Direction != "" && event.Direction != ClientToRemote && event.Direction != RemoteToClient {
		return fmt.Errorf("%w: invalid direction", ErrInvalidEvent)
	}
	if event.Timing != TimingObserved && event.Timing != TimingDerived {
		return fmt.Errorf("%w: invalid timing", ErrInvalidEvent)
	}
	if event.OccurredAtMs < 0 || event.ProcessedAtMs != nil && *event.ProcessedAtMs < 0 {
		return fmt.Errorf("%w: negative timestamp", ErrInvalidEvent)
	}
	if err := event.Summary.validate(); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidEvent, err)
	}
	return nil
}

func (envelope StreamEnvelope) Validate() error {
	if envelope.Version != ProtocolVersion {
		return fmt.Errorf("%w: unsupported protocol version %d", ErrInvalidEvent, envelope.Version)
	}
	if !validRequiredString(envelope.SessionID, 128) || envelope.ServerNowMs < 0 || len(envelope.Events) > 200 {
		return fmt.Errorf("%w: malformed envelope", ErrInvalidEvent)
	}
	for index := range envelope.Events {
		if envelope.Events[index].SessionID != envelope.SessionID {
			return fmt.Errorf("%w: event %d belongs to another session", ErrInvalidEvent, index)
		}
		if err := envelope.Events[index].Validate(); err != nil {
			return fmt.Errorf("event %d: %w", index, err)
		}
	}
	return nil
}

func (summary Summary) validate() error {
	stringsWithLimits := []struct {
		value string
		limit int
	}{
		{summary.Protocol, 16}, {summary.ClientIP, 64}, {summary.RemoteIP, 64},
		{summary.FlowKey, 512}, {summary.DNSName, 253}, {summary.DNSType, 32},
		{summary.Hostname, 253}, {summary.Confidence, 32}, {summary.Verdict, 32},
		{summary.VerdictSource, 32},
	}
	for _, candidate := range stringsWithLimits {
		if len(candidate.value) > candidate.limit || strings.ContainsRune(candidate.value, '\x00') {
			return errors.New("oversized or invalid summary string")
		}
	}
	if summary.ClientPort != nil && *summary.ClientPort == 0 || summary.RemotePort != nil && *summary.RemotePort == 0 {
		return errors.New("port must be greater than zero")
	}
	if summary.TCPFlags != nil && *summary.TCPFlags > 0x1ff {
		return errors.New("tcp flags exceed the header bit range")
	}
	return nil
}

func (kind EventKind) valid() bool {
	switch kind {
	case KindDNS, KindFlow, KindBurst, KindAttribution, KindDestination, KindRoute, KindGate, KindHealth:
		return true
	default:
		return false
	}
}

func (stage Stage) valid() bool {
	switch stage {
	case StageClient, StageGatewayIngress, StageDNS, StageConntrack, StageHeaderCapture, StageGateQueue, StageForward, StageNAT, StageRemote, StageAttribution, StageDestination, StageRoute, StageHealth:
		return true
	default:
		return false
	}
}

func validRequiredString(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsRune(value, '\x00')
}
