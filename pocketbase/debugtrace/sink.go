package debugtrace

import "sync/atomic"

// BurstInput is the packet-free metadata accepted by the future burst
// coalescer. Sequence is intentionally absent: the hub is its sole allocator.
type BurstInput struct {
	SessionID    string
	TraceID      string
	FlowKey      string
	Protocol     string
	Direction    Direction
	OccurredAtMs int64
	WireBytes    uint64
	PayloadBytes uint64
	PacketCount  uint64
	TCPFlags     uint16
}

// Sink methods are non-blocking. False means the bounded ingress rejected the
// value; producers must never retry synchronously or alter forwarding results.
type Sink interface {
	TryEmit(Event) bool
	TryBurst(BurstInput) bool
}

// NopSink is safe to share and performs no allocations or goroutine work.
type NopSink struct{}

func (NopSink) TryEmit(Event) bool       { return true }
func (NopSink) TryBurst(BurstInput) bool { return true }

type ingressKind uint8

const (
	ingressEvent ingressKind = iota
	ingressBurst
)

type ingressItem struct {
	kind  ingressKind
	event Event
	burst BurstInput
}

// Ingress is the bounded producer boundary used by the trace hub. The hub
// drains items later; producers only attempt a channel send.
type Ingress struct {
	items    chan ingressItem
	rejected atomic.Uint64
}

func NewIngress(capacity int) *Ingress {
	if capacity < 1 {
		capacity = 1
	}
	return &Ingress{items: make(chan ingressItem, capacity)}
}

func (ingress *Ingress) TryEmit(event Event) bool {
	select {
	case ingress.items <- ingressItem{kind: ingressEvent, event: event}:
		return true
	default:
		ingress.rejected.Add(1)
		return false
	}
}

func (ingress *Ingress) TryBurst(burst BurstInput) bool {
	select {
	case ingress.items <- ingressItem{kind: ingressBurst, burst: burst}:
		return true
	default:
		ingress.rejected.Add(1)
		return false
	}
}

func (ingress *Ingress) Rejected() uint64 { return ingress.rejected.Load() }
