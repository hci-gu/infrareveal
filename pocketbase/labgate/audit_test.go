package labgate

import (
	"context"
	"errors"
	"myapp/data"
	"myapp/testsupport"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"

	"myapp/netmeta"
)

func TestOptionalGateSchemaAndOrderedAuditLifecycle(t *testing.T) {
	app := testsupport.App(t)
	if err := data.EnsureGateAudit(app); err != nil {
		t.Fatal(err)
	}
	gateCollection, err := app.FindCollectionByNameOrId("gate_events")
	if err != nil {
		t.Fatal(err)
	}
	if gateCollection.CreateRule != nil || gateCollection.UpdateRule != nil || gateCollection.DeleteRule != nil {
		t.Fatal("browser mutation rules are not locked")
	}
	if gateCollection.ListRule != nil || gateCollection.ViewRule != nil {
		t.Fatal("raw audit visibility must require admin authentication")
	}
	for _, index := range []string{"gate_session_time", "gate_session_decision"} {
		if !hasCollectionIndex(gateCollection, index) {
			t.Fatalf("missing index %s", index)
		}
	}
	for _, field := range []string{"mode", "direction", "wire_bytes", "payload_bytes", "tcp_flags"} {
		if gateCollection.Fields.GetByName(field) == nil {
			t.Fatalf("missing gate packet metadata field %s", field)
		}
	}
	session := testsupport.Save(t, app, "sessions", map[string]any{
		"name":   "Audit",
		"active": true,
	})
	tuple, _ := netmetaTuple()
	queuedAt := time.Now().UTC().Add(-50 * time.Millisecond)
	decision := Decision{ID: "decision-1", SessionID: session.Id, FlowKey: tuple.Key(), ClientIP: tuple.ClientIP.String(), ClientPort: tuple.ClientPort, RemoteIP: tuple.RemoteIP.String(), RemotePort: tuple.RemotePort, Protocol: tuple.Protocol, Mode: ModeStrict, Direction: netmeta.ClientToRemote, WireBytes: 64, PayloadBytes: 4, TCPFlags: 0x12, PacketCount: 2, State: DecisionQueued, QueuedAt: queuedAt, Deadline: queuedAt.Add(time.Second)}
	writer := NewAuditWriter(app, 8)
	if !writer.TryQueued(decision) {
		t.Fatal("queued audit rejected")
	}
	decision.State, decision.Verdict, decision.Source = DecisionApproved, VerdictAccept, SourceOperator
	decision.Actor, decision.DecidedAt, decision.WaitMS = "tester", time.Now().UTC(), 50
	if !writer.TryTerminal(decision) {
		t.Fatal("terminal audit rejected")
	}
	duplicate := decision
	duplicate.State, duplicate.Actor = DecisionRejected, "late verdict"
	if !writer.TryTerminal(duplicate) {
		t.Fatal("duplicate terminal audit rejected")
	}
	duplicate.State = DecisionQueued
	if !writer.TryQueued(duplicate) {
		t.Fatal("late queued audit rejected")
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
	app := testsupport.App(t)
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

func TestAuditLookupFailureDoesNotCreateARecord(t *testing.T) {
	app, decision := newAuditFixture(t)
	lookupErr := errors.New("audit lookup unavailable")
	writer := AuditWriter{app: failedAuditLookup{App: app, err: lookupErr}}
	for _, terminal := range []bool{false, true} {
		if err := writer.persistDecision(decision, terminal); !errors.Is(err, lookupErr) {
			t.Fatalf("terminal=%t: lookup failure was replaced by a write: %v", terminal, err)
		}
	}
	if records, err := app.FindAllRecords("gate_events"); err != nil || len(records) != 0 {
		t.Fatalf("failed lookup created audit records: count=%d error=%v", len(records), err)
	}
}

type failedAuditLookup struct {
	core.App
	err error
}

func (app failedAuditLookup) FindFirstRecordByFilter(any, string, ...dbx.Params) (*core.Record, error) {
	return nil, app.err
}
