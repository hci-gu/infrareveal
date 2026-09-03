package debugtrace

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestSharedPipelineEventFixture(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "testdata", "pipeline-event-v1.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}

	var envelope StreamEnvelope
	if err := json.Unmarshal(data, &envelope); err != nil {
		t.Fatal(err)
	}
	if err := envelope.Validate(); err != nil {
		t.Fatal(err)
	}

	clientPort := uint16(53120)
	remotePort := uint16(443)
	wireBytes := uint64(1514)
	payloadBytes := uint64(1448)
	packetCount := uint64(1)
	tcpFlags := uint16(2)
	captureComplete := true
	processedAt := int64(1788343200002)
	expected := Event{
		ID: "fixture-flow-1", Sequence: 41, SessionID: "fixture-session", TraceID: "fixture-trace-1",
		ParentID: "fixture-parent-1", Kind: KindFlow, Stage: StageGatewayIngress,
		Direction: ClientToRemote, OccurredAtMs: 1788343200000, ProcessedAtMs: &processedAt, Timing: TimingObserved,
		Summary: Summary{
			Protocol: "tcp", ClientIP: "10.42.0.18", ClientPort: &clientPort,
			RemoteIP: "142.250.74.14", RemotePort: &remotePort,
			FlowKey: "tcp|10.42.0.18|53120|142.250.74.14|443", DNSName: "example.org",
			DNSType: "A", Hostname: "edge.example.org", Confidence: "high",
			WireBytes: &wireBytes, PayloadBytes: &payloadBytes, PacketCount: &packetCount,
			TCPFlags: &tcpFlags, Verdict: "approved", VerdictSource: "operator",
			CaptureComplete: &captureComplete,
		},
	}
	if len(envelope.Events) != 1 || !reflect.DeepEqual(envelope.Events[0], expected) {
		t.Fatalf("fixture decoded unexpectedly: %#v", envelope.Events)
	}
}

func TestEventValidationRejectsUnsafeValues(t *testing.T) {
	valid := Event{
		ID: "event", SessionID: "session", TraceID: "trace", Kind: KindHealth,
		Stage: StageHealth, OccurredAtMs: 1, Timing: TimingObserved,
	}
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}

	invalid := valid
	invalid.Summary.DNSName = string(make([]byte, 254))
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected oversized DNS name to be rejected")
	}

	invalid = valid
	invalid.Kind = "raw_packet"
	if err := invalid.Validate(); err == nil {
		t.Fatal("expected unknown event kind to be rejected")
	}
}

func TestIngressRejectsWithoutBlockingWhenFull(t *testing.T) {
	ingress := NewIngress(1)
	if !ingress.TryEmit(Event{}) {
		t.Fatal("first event should fit")
	}
	if ingress.TryBurst(BurstInput{}) {
		t.Fatal("full ingress should reject")
	}
	if got := ingress.Rejected(); got != 1 {
		t.Fatalf("rejected = %d, want 1", got)
	}
}

func TestNopSinkAlwaysAccepts(t *testing.T) {
	var sink Sink = NopSink{}
	if !sink.TryEmit(Event{}) || !sink.TryBurst(BurstInput{}) {
		t.Fatal("disabled tracing must be an inert accepted operation")
	}
}
