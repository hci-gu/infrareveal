package labgate

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"

	_ "myapp/migrations"
	"myapp/netmeta"
)

func TestGateMigrationAndOrderedAuditLifecycle(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	gateCollection, err := app.FindCollectionByNameOrId("gate_events")
	if err != nil {
		t.Fatal(err)
	}
	flows, _ := app.FindCollectionByNameOrId("flows")
	if gateCollection.CreateRule != nil || gateCollection.UpdateRule != nil || gateCollection.DeleteRule != nil {
		t.Fatal("browser mutation rules are not locked")
	}
	if (gateCollection.ListRule == nil) != (flows.ListRule == nil) || (gateCollection.ViewRule == nil) != (flows.ViewRule == nil) {
		t.Fatal("visibility does not follow flow data")
	}
	for _, index := range []string{"idx_gate_events_session_queued", "idx_gate_events_session_decision", "idx_gate_events_session_flow"} {
		if !hasCollectionIndex(gateCollection, index) {
			t.Fatalf("missing index %s", index)
		}
	}
	for _, field := range []string{"mode", "direction", "wire_bytes", "payload_bytes", "tcp_flags"} {
		if gateCollection.Fields.GetByName(field) == nil {
			t.Fatalf("missing gate packet metadata field %s", field)
		}
	}
	sessions, _ := app.FindCollectionByNameOrId("sessions")
	session := core.NewRecord(sessions)
	session.Set("name", "Audit")
	session.Set("active", true)
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	tuple, _ := netmetaTuple()
	queuedAt := time.Now().UTC().Add(-50 * time.Millisecond)
	decision := Decision{ID: "decision-1", SessionID: session.Id, FlowKey: tuple.Key(), Tuple: tuple, ClientIP: tuple.ClientIP.String(), ClientPort: tuple.ClientPort, RemoteIP: tuple.RemoteIP.String(), RemotePort: tuple.RemotePort, Protocol: tuple.Protocol, Mode: ModeStrict, Direction: netmeta.ClientToRemote, WireBytes: 64, PayloadBytes: 4, TCPFlags: 0x12, PacketCount: 2, State: DecisionQueued, QueuedAt: queuedAt, Deadline: queuedAt.Add(time.Second)}
	writer := NewAuditWriter(app, 8)
	if !writer.TryQueued(decision) {
		t.Fatal("queued audit rejected")
	}
	decision.State, decision.Verdict, decision.Source = DecisionApproved, VerdictAccept, SourceOperator
	decision.Actor, decision.DecidedAt, decision.WaitMS = "tester", time.Now().UTC(), 50
	if !writer.TryTerminal(decision) {
		t.Fatal("terminal audit rejected")
	}
	bypass := decision
	bypass.ID, bypass.State, bypass.Source, bypass.Reason = "decision-bypass", DecisionBypassed, SourceOverflow, "capacity reached"
	bypass.QueuedAt, bypass.DecidedAt, bypass.WaitMS = time.Now().UTC(), time.Now().UTC(), 0
	if !writer.TryTerminal(bypass) {
		t.Fatal("terminal-only bypass audit rejected")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Flush(ctx); err != nil {
		t.Fatal(err)
	}
	if writer.DroppedForSession(session.Id) != 0 {
		t.Fatal("successful session reported audit loss")
	}
	if err := writer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	records, err := app.FindAllRecords("gate_events")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || countAuditState(records, "approved") != 1 || countAuditState(records, "bypassed") != 1 {
		t.Fatalf("audit records = %#v", records)
	}
	approved := recordWithAuditState(records, "approved")
	if approved == nil || approved.GetString("actor") != "tester" || approved.GetInt("packet_count") != 2 || approved.GetString("mode") != "strict" || approved.GetInt("wire_bytes") != 64 {
		t.Fatalf("approved audit metadata = %#v", approved)
	}
}

func countAuditState(records []*core.Record, state string) int {
	count := 0
	for _, record := range records {
		if record.GetString("state") == state {
			count++
		}
	}
	return count
}

func recordWithAuditState(records []*core.Record, state string) *core.Record {
	for _, record := range records {
		if record.GetString("state") == state {
			return record
		}
	}
	return nil
}

func hasCollectionIndex(collection *core.Collection, name string) bool {
	for _, index := range collection.Indexes {
		if strings.Contains(index, name) {
			return true
		}
	}
	return false
}

func netmetaTuple() (netmeta.FlowTuple, bool) {
	return netmeta.NewFlowTuple("tcp", netip.MustParseAddr("10.0.0.2"), 50000, netip.MustParseAddr("1.1.1.1"), 443)
}

func TestAuditWriterRejectsAfterCloseWithoutPanicking(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = app.ResetBootstrapState() }()
	writer := NewAuditWriter(app, 8)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := writer.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if writer.TryQueued(Decision{}) || writer.Dropped() != 1 {
		t.Fatal("closed audit writer accepted work")
	}
}
