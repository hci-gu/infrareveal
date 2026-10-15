package routing

import (
	"errors"
	"myapp/data"
	"myapp/testsupport"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/core"
)

func TestEvidenceReaderAndRetentionKeepAnchorsInCallerTransaction(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	now := time.Now().Truncate(time.Millisecond)
	binding := target{"9.9.9.9", "tcp", 443}.binding()
	chunk := data.TrafficChunk{ID: data.NewID(), Session: session, NetworkEpoch: "epoch", DestinationIP: "9.9.9.9", Protocol: "tcp", DestinationPort: 443, StartMS: now.UnixMilli(), Samples: []data.Sample{}}
	if _, err := data.Write(app, "traffic_chunks", chunk); err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	for i, offset := range []time.Duration{-3 * time.Minute, -2 * time.Minute, -time.Minute, time.Second} {
		e := data.RouteEvidence{ID: data.NewID(), Session: session, Kind: "path", NetworkContext: "network", NetworkEpoch: "epoch", BindingKey: binding, DestinationIP: "9.9.9.9", Protocol: "tcp", DestinationPort: 443, AttemptID: data.NewID(), Revision: 1, MeasuredMS: now.Add(offset).UnixMilli(), AvailableMS: now.Add(offset).UnixMilli(), ValidUntilMS: now.Add(time.Hour).UnixMilli(), Hops: []data.Hop{}}
		if _, err := data.Write(app, "route_evidence", e); err != nil {
			t.Fatal(i, err)
		}
		ids = append(ids, e.ID)
	}
	invalid := data.RouteEvidence{ID: data.NewID(), Session: session, Kind: "network_invalidated", NetworkEpoch: "epoch", AvailableMS: now.Add(2 * time.Second).UnixMilli(), Hops: []data.Hop{}}
	if _, err := data.Write(app, "route_evidence", invalid); err != nil {
		t.Fatal(err)
	}
	page, err := QueryEvidence(app, EvidenceQuery{Session: session, From: now, To: now.Add(3 * time.Second), Limit: 2})
	if err != nil || !page.More || len(page.Records) != 2 || page.Records[0].Id != ids[2] || page.Records[1].Id != ids[3] {
		t.Fatalf("missing anchor or page cap: %+v %v", page, err)
	}
	second, err := QueryEvidence(app, EvidenceQuery{Session: session, From: now, To: now.Add(3 * time.Second), Limit: 2, Offset: 2})
	if err != nil || second.More || len(second.Records) != 1 || second.Records[0].Id != invalid.ID {
		t.Fatalf("missing invalidation: %+v %v", second, err)
	}
	rollback := errors.New("rollback")
	err = app.RunInTransaction(func(tx core.App) error {
		if err := RetainSession(tx, session, now); err != nil {
			return err
		}
		return rollback
	})
	if !errors.Is(err, rollback) || len(routeRows(t, app)) != 5 {
		t.Fatal("retention escaped caller transaction", err)
	}
	if err := app.RunInTransaction(func(tx core.App) error { return RetainSession(tx, session, now) }); err != nil {
		t.Fatal(err)
	}
	rows := routeRows(t, app)
	if len(rows) != 3 {
		t.Fatal(rows)
	}
	if EvidenceAt(rows, "epoch", binding, now.UnixMilli()) == nil {
		t.Fatal("lost pre-window anchor")
	}
	if EvidenceAt(rows, "epoch", binding, now.Add(2*time.Second).UnixMilli()) != nil {
		t.Fatal("lost invalidation")
	}
}
func TestLateEnrichmentCannotSupersedeNewerMeasurement(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	first := mustReserve(t, r, b, false, now)
	s := useful(now, first.Attempt)
	if err := r.finish(first, s, now, true); err != nil {
		t.Fatal(err)
	}
	later := now.Add(time.Second)
	second := mustReserve(t, r, b, true, later)
	next := useful(later, second.Attempt)
	next.Hops[2].Address = "8.8.8.8"
	if err := r.finish(second, next, later, true); err != nil {
		t.Fatal(err)
	}
	s.Hops[2].Evidence = map[string]InterfaceEvidence{"8.8.4.4": {PTR: "late.example"}}
	if err := r.enrichPublication(first, s, later.Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	rows := routeRows(t, app)
	if len(rows) != 2 {
		t.Fatal("late enrichment changed a superseded path")
	}
	selected := EvidenceAt(rows, b.Epoch, b.Target.binding(), later.Add(2*time.Second).UnixMilli())
	if selected == nil || selected.AttemptID != second.Attempt {
		t.Fatal(selected)
	}
}
func TestInvalidationDominatesSameMillisecondEnrichment(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now().Truncate(time.Millisecond)
	b := bindingFor(t, r, session, "9.9.9.9", now)
	a := mustReserve(t, r, b, false, now)
	s := useful(now, a.Attempt)
	if err := r.finish(a, s, now, true); err != nil {
		t.Fatal(err)
	}
	s.Hops[2].Evidence = map[string]InterfaceEvidence{"8.8.4.4": {PTR: "example.test"}}
	if err := r.enrichPublication(a, s, now); err != nil {
		t.Fatal(err)
	}
	if _, err := r.activateNetwork(session, "changed", now); err != nil {
		t.Fatal(err)
	}
	if got := EvidenceAt(routeRows(t, app), b.Epoch, b.Target.binding(), now.Add(time.Second).UnixMilli()); got != nil {
		t.Fatal("same-timestamp enrichment resurrected invalidated geometry", got)
	}
}
func TestManualLimitsRetainNetworkAndStorageBoundaries(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	cfg := defaultConfig()
	cfg.ManualAttempts = 1
	cfg.HourlyAttempts = 2
	r := newEvidenceStore(app, nil, cfg)
	now := time.Now()
	b := bindingFor(t, r, session, "9.9.9.9", now)
	mustReserve(t, r, b, true, now)
	a, err := r.reserve(b, true, now.Add(time.Second))
	if err != nil || a.Reason != "manual_budget" {
		t.Fatal(a, err)
	}
	b.Target.IP = "8.8.8.8"
	mustReserve(t, r, b, false, now.Add(time.Second))
	cfg.ManualAttempts = 2
	r.config = cfg
	a, err = r.reserve(b, true, now.Add(2*time.Second))
	if err != nil || a.Reason != "hourly_budget" {
		t.Fatal(a, err)
	}
}
func TestUDPv6OnlyUsesQualifiedMethod(t *testing.T) {
	app := testsupport.App(t)
	session := testSession(t, app)
	r := newEvidenceStore(app, nil, defaultConfig())
	now := time.Now()
	b := bindingFor(t, r, session, "2606:4700:4700::1111", now)
	b.Target.Protocol = "udp"
	a := mustReserve(t, r, b, false, now)
	if a.Method != "icmp-paris" {
		t.Fatal(a)
	}
	if err := r.finish(a, snapshot{Method: a.Method, Measured: now, Finished: now, Status: "unavailable"}, now, true); err != nil {
		t.Fatal(err)
	}
	denied, err := r.reserve(b, false, now.Add(time.Second))
	if err != nil || denied.Reason != "comparison_finished" {
		t.Fatal(denied, err)
	}
}

func TestNewestExpiredPathNeverFallsBackToOlderPublication(t *testing.T) {
	rows := []data.RouteEvidence{
		{ID: "new", Kind: "path", NetworkEpoch: "epoch", BindingKey: "binding", AvailableMS: 20, ValidUntilMS: 30},
		{ID: "old", Kind: "path", NetworkEpoch: "epoch", BindingKey: "binding", AvailableMS: 10, ValidUntilMS: 100},
	}
	if got := EvidenceAt(rows, "epoch", "binding", 15); got == nil || got.ID != "old" {
		t.Fatal(got)
	}
	if got := EvidenceAt(rows, "epoch", "binding", 25); got == nil || got.ID != "new" {
		t.Fatal(got)
	}
	if got := EvidenceAt(rows, "epoch", "binding", 30); got != nil {
		t.Fatal("resurrected old path", got)
	}
	if got := EvidenceAt(rows, "epoch", "different-binding", 25); got != nil {
		t.Fatal("binding mismatch", got)
	}
}
