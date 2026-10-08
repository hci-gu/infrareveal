package labgate

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"myapp/debugtrace"
	"myapp/netmeta"
)

func TestGateTraceAndControlMatchSharedContract(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "gate-event-contract-v1.json"))
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Record struct {
			ID            string            `json:"decision_id"`
			SessionID     string            `json:"session"`
			FlowKey       string            `json:"flow_key"`
			ClientIP      string            `json:"client_ip"`
			RemoteIP      string            `json:"destination_ip"`
			ClientPort    uint16            `json:"source_port"`
			RemotePort    uint16            `json:"destination_port"`
			Protocol      string            `json:"protocol"`
			Mode          Mode              `json:"mode"`
			Direction     netmeta.Direction `json:"direction"`
			WireBytes     uint32            `json:"wire_bytes"`
			PayloadBytes  uint32            `json:"payload_bytes"`
			TCPFlags      uint16            `json:"tcp_flags"`
			PacketCount   int               `json:"packet_count"`
			State         DecisionState     `json:"state"`
			Actor         string            `json:"actor"`
			Reason        string            `json:"reason"`
			VerdictSource VerdictSource     `json:"verdict_source"`
			QueuedAt      time.Time         `json:"queued_at"`
			DecidedAt     time.Time         `json:"decided_at"`
			WaitMS        int64             `json:"wait_ms"`
		} `json:"record"`
		Live            []debugtrace.Event `json:"live"`
		ControlDecision map[string]any     `json:"controlDecision"`
	}
	if err := json.Unmarshal(data, &fixture); err != nil {
		t.Fatal(err)
	}
	record := fixture.Record
	decision := Decision{
		ID: record.ID, SessionID: record.SessionID, FlowKey: record.FlowKey,
		ClientIP: record.ClientIP, RemoteIP: record.RemoteIP, ClientPort: record.ClientPort, RemotePort: record.RemotePort,
		Protocol: record.Protocol, Mode: record.Mode, Direction: record.Direction,
		WireBytes: record.WireBytes, PayloadBytes: record.PayloadBytes, TCPFlags: record.TCPFlags, PacketCount: record.PacketCount,
		QueuedAt: record.QueuedAt, Deadline: record.QueuedAt.Add(10 * time.Second), State: DecisionQueued,
	}
	traces := &traceCollector{}
	controller := &Controller{trace: traces}
	controller.emitDecision(decision, "queued")
	queued := decisionForAPI(decision)
	if queued.DecidedAtMS != 0 || queued.Verdict != "" || queued.WaitMS != 0 {
		t.Fatalf("queued control response has terminal values: %+v", queued)
	}
	decision.State, decision.Actor, decision.Reason = record.State, record.Actor, record.Reason
	decision.Verdict, decision.Source = VerdictDrop, record.VerdictSource
	decision.DecidedAt, decision.WaitMS = record.DecidedAt, record.WaitMS
	controller.emitDecision(decision, "verdict")
	if len(traces.events) != len(fixture.Live) {
		t.Fatalf("live event count=%d, want %d", len(traces.events), len(fixture.Live))
	}
	for index, expected := range fixture.Live {
		actual := traces.events[index]
		actual.Sequence = expected.Sequence // Assigned by the trace hub after emission.
		if err := actual.Validate(); err != nil {
			t.Fatal(err)
		}
		if !reflect.DeepEqual(actual, expected) {
			t.Fatalf("live contract event %d:\ngot  %+v\nwant %+v", index, actual, expected)
		}
	}
	encoded, err := json.Marshal(decisionForAPI(decision))
	if err != nil {
		t.Fatal(err)
	}
	var actual map[string]any
	if err := json.Unmarshal(encoded, &actual); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(actual, fixture.ControlDecision) {
		t.Fatalf("control contract:\ngot  %s\nwant %+v", encoded, fixture.ControlDecision)
	}
}

func TestOverflowTraceSharesDurableDecisionIdentity(t *testing.T) {
	traces, audit := &traceCollector{}, &auditCollector{}
	controller := &Controller{trace: traces, audit: audit}
	packet := tcpPacket(1, 50000)
	if !controller.recordBypass("session-fixture", ModeFlow, packet, SourceOverflow, "gate capacity reached", nil) {
		t.Fatal("overflow audit rejected")
	}
	decisions := audit.terminal()
	if len(decisions) != 1 || len(traces.events) != 1 {
		t.Fatalf("overflow evidence: decisions=%v events=%v", decisions, traces.events)
	}
	decision, event := decisions[0], traces.events[0]
	if decision.State != DecisionBypassed || event.ID != fmt.Sprintf("gate:%s:verdict", decision.ID) || event.ParentID != fmt.Sprintf("gate:%s:queued", decision.ID) {
		t.Fatalf("overflow identity diverged: decision=%+v event=%+v", decision, event)
	}
	if event.Stage != debugtrace.StageGateQueue || event.Summary.Verdict != "accept" || event.Summary.WireBytes == nil || *event.Summary.WireBytes != uint64(packet.WireBytes) {
		t.Fatalf("overflow live semantics changed: %+v", event)
	}
	controller.recordBypass("session-fixture", ModeFlow, packet, SourceSystem, "gate intake inactive", nil)
	if len(audit.terminal()) != 1 || traces.events[1].ID != fmt.Sprintf("gate-bypass:%d:%d", packet.ID, packet.OccurredAt.UnixMilli()) {
		t.Fatal("unaudited bypass lost its independent identity")
	}
}
