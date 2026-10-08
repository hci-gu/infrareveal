package gateway

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"myapp/labgate"
	"myapp/netmeta"
)

// Exercise the gateway boundary with the real controller and durable writer.
// Only the kernel queue is replaced, so ordering failures cannot hide behind a
// fake Disarm/Flush implementation.
func TestGatewayTransitionsDrainHeldGateBeforeAuditCompletion(t *testing.T) {
	for _, action := range []string{"end session", "clear"} {
		t.Run(action, func(t *testing.T) {
			app := ephemeralTestApp(t)
			g := testRuntime(t, app)
			g.Register()
			session := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": action, "active": true})
			queue := &lifecycleQueue{ready: make(chan struct{}), packets: make(chan labgate.QueuedPacket, 1), verdicts: make(chan labgate.Verdict, 1)}
			g.audit = labgate.NewAuditWriter(app, 8)
			config := labgate.Config{Enabled: true, FailOpen: true, ControlTokenFile: "test-token", FlowTimeout: time.Minute}
			var err error
			g.gate, err = labgate.NewController(context.Background(), config, queue, nil, nil, g.audit)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				defer cancel()
				if err := g.Close(ctx); err != nil {
					t.Error(err)
				}
			})
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			waitForGate := func(ready func(labgate.Status) bool) {
				t.Helper()
				for {
					status, err := g.gate.Status(ctx)
					if err != nil {
						t.Fatal(err)
					}
					if ready(status) {
						return
					}
					time.Sleep(time.Millisecond)
				}
			}
			waitForGate(func(status labgate.Status) bool { return status.ListenerReady })
			client := netip.MustParseAddr("10.0.0.50")
			if _, err := g.gate.Arm(ctx, labgate.ArmRequest{SessionID: session.Id, Mode: labgate.ModeFlow, Clients: []netip.Addr{client}}); err != nil {
				t.Fatal(err)
			}
			queue.packets <- labgate.QueuedPacket{ID: 1, QueueMode: labgate.ModeFlow, Tuple: netmeta.FlowTuple{Protocol: "tcp", ClientIP: client, ClientPort: 53000, RemoteIP: netip.MustParseAddr("1.1.1.1"), RemotePort: 443}, Direction: netmeta.ClientToRemote, TCPFlags: 0x02, WireBytes: 60, OccurredAt: time.Now()}
			waitForGate(func(status labgate.Status) bool { return status.HeldPackets == 1 })

			if action == "clear" {
				result, err := g.Clear(ctx)
				if err != nil || result.Deleted["gate_events"] != 1 {
					t.Fatalf("clear must flush the terminal record before deleting it: %+v, %v", result, err)
				}
				count, err := app.CountRecords("gate_events")
				if err != nil || count != 0 || g.CurrentSessionID() != session.Id {
					t.Fatalf("clear left audit data or changed session: count=%d session=%s err=%v", count, g.CurrentSessionID(), err)
				}
			} else {
				if err := app.RunInTransaction(func(tx core.App) error {
					record, err := tx.FindRecordById("sessions", session.Id)
					if err != nil {
						return err
					}
					record.Set("active", false)
					return tx.Save(record)
				}); err != nil {
					t.Fatal(err)
				}
				stored, err := app.FindRecordById("sessions", session.Id)
				if err != nil || !stored.GetBool("gate_audit_complete") || stored.GetInt("gate_audit_drops") != 0 || g.CurrentSessionID() != "" {
					t.Fatalf("session completion did not flush accepted audit: %v", err)
				}
				events, err := app.FindRecordsByFilter("gate_events", "", "", 10, 0)
				if err != nil || len(events) != 1 || events[0].GetString("state") != string(labgate.DecisionDrained) || events[0].GetDateTime("decided_at").IsZero() {
					t.Fatalf("terminal audit missing after session completion: %v %v", events, err)
				}
			}
			select {
			case verdict := <-queue.verdicts:
				if verdict != labgate.VerdictAccept {
					t.Fatalf("transition failed open: %s", verdict)
				}
			default:
				t.Fatal("transition completed before releasing held packet")
			}
			status, err := g.gate.Status(ctx)
			if err != nil || status.Armed || status.HeldPackets != 0 || status.State != labgate.StateOff {
				t.Fatalf("gate did not disarm: %+v %v", status, err)
			}
		})
	}
}

type lifecycleQueue struct {
	ready    chan struct{}
	packets  chan labgate.QueuedPacket
	verdicts chan labgate.Verdict
}

func (q *lifecycleQueue) Ready() <-chan struct{} { return q.ready }
func (q *lifecycleQueue) Start(ctx context.Context, handle func(labgate.QueuedPacket)) error {
	close(q.ready)
	for {
		select {
		case packet := <-q.packets:
			handle(packet)
		case <-ctx.Done():
			return nil
		}
	}
}
func (q *lifecycleQueue) SetVerdict(_ uint32, verdict labgate.Verdict) error {
	q.verdicts <- verdict
	return nil
}
func (q *lifecycleQueue) Stats() labgate.QueueStats { return labgate.QueueStats{} }
func (q *lifecycleQueue) Close() error              { return nil }
