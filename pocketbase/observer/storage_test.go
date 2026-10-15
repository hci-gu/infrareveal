package observer

import (
	"errors"
	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/testsupport"
	"testing"
)

func captureApp(t *testing.T) (*pocketbase.PocketBase, *aggregate, map[string]data.Destination) {
	t.Helper()
	app := testsupport.App(t)
	a := testAggregate()
	d := testDestination()
	_, err := data.Write(app, "sessions", data.Session{ID: a.session, Name: "test", StartedMS: 100000, Active: true, Policy: a.policy})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = beginCapture(app, a.session, a.epoch); err != nil {
		t.Fatal(err)
	}
	return app, a, map[string]data.Destination{d.ID: d}
}
func storedChunks(t *testing.T, app core.App) []data.TrafficChunk {
	t.Helper()
	c, e := readRecords[data.TrafficChunk](app, "traffic_chunks", "1=1", nil)
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func commitAggregate(t *testing.T, app core.App, a *aggregate, d map[string]data.Destination, now int64) {
	t.Helper()
	chunks := a.snapshot(now)
	_, err := persistCapture(app, a.session, a.epoch, a.generation, chunks, d, []data.CaptureInterval{{ID: "coverage0000001", Session: a.session, CaptureEpoch: a.epoch, StartMS: 100000, EndMS: now, Quality: "complete"}}, data.CaptureHealth{ConfirmedMS: now, Quality: "complete"})
	if err != nil {
		t.Fatal(err)
	}
}

func TestCorrectionIsAtomicAndStaleFlushCannotResurrectOldGroup(t *testing.T) {
	app, a, d := captureApp(t)
	a.packet(testPacket(100000, 40000), "network", testDestination())
	old := a.snapshot(100050)
	if _, err := persistCapture(app, a.session, a.epoch, a.generation, old, d, nil, data.CaptureHealth{}); err != nil {
		t.Fatal(err)
	}
	answer(a, "svt.se", 100100)
	commitAggregate(t, app, a, d, 100200)
	chunks := storedChunks(t, app)
	if len(chunks) != 1 || chunks[0].ServiceKey != "svt.se" || totals(chunks)[0] != 150 {
		t.Fatalf("old aggregate survived correction: %#v", chunks)
	}
	if _, err := persistCapture(app, a.session, a.epoch, old[0].Generation, old, d, nil, data.CaptureHealth{}); !errors.Is(err, errStaleFlush) {
		t.Fatalf("stale flush accepted: %v", err)
	}
	if got := totals(storedChunks(t, app))[0]; got != 150 {
		t.Fatalf("stale write changed total %d", got)
	}
	// Fail after the old row was removed: the surrounding transaction restores it.
	a.packet(testPacket(100250, 40001), "network", testDestination())
	snapshot := a.snapshot(100300)
	if _, err := persistCapture(app, a.session, a.epoch, a.generation, snapshot, map[string]data.Destination{}, nil, data.CaptureHealth{}); err == nil {
		t.Fatal("missing snapshot should reject complete transaction")
	}
	if got := totals(storedChunks(t, app))[0]; got != 150 {
		t.Fatalf("failed replacement was partially applied: %d", got)
	}
}

func TestRestartSealsHistoryAndRejectsPriorEpoch(t *testing.T) {
	app, a, d := captureApp(t)
	a.packet(testPacket(100000, 40000), "network", testDestination())
	commitAggregate(t, app, a, d, 100050)
	old := a.snapshot(100060)
	if _, err := beginCapture(app, a.session, "newcapture00001"); err != nil {
		t.Fatal(err)
	}
	if _, err := persistCapture(app, a.session, a.epoch, a.generation, old, d, nil, data.CaptureHealth{}); !errors.Is(err, errStaleFlush) {
		t.Fatal("old epoch still allowed writes", err)
	}
	a = newAggregate(a.session, "newcapture00001", a.policy, 256)
	a.packet(testPacket(100100, 40000), "network", testDestination())
	commitAggregate(t, app, a, d, 100150)
	chunks := storedChunks(t, app)
	if len(chunks) != 2 || totals(chunks)[0] != 300 {
		t.Fatalf("restart overwrote earlier five-second chunk: %#v", chunks)
	}
	for _, c := range chunks {
		if c.CaptureEpoch != "newcapture00001" && !c.Sealed {
			t.Fatal("old label not sealed")
		}
	}
}

func TestRetentionFencePreventsFlushRestoringRemovedSamples(t *testing.T) {
	app, a, d := captureApp(t)
	a.packet(testPacket(100000, 40000), "network", testDestination())
	a.packet(testPacket(100100, 40000), "network", testDestination())
	commitAggregate(t, app, a, d, 100150)
	if err := RebuildBlocks(app, a.session, 100150); err != nil {
		t.Fatal(err)
	}
	var before data.ActivityBlock
	rows, e := readRecords[data.ActivityBlock](app, "activity_blocks", "1=1", nil)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	before = rows[0]
	err := app.RunInTransaction(func(tx core.App) error {
		if err := PruneSession(tx, a.session, 100100); err != nil {
			return err
		}
		_, err := tx.DB().NewQuery("UPDATE sessions SET retained_from_ms=100100 WHERE id={:s}").Bind(dbx.Params{"s": a.session}).Execute()
		return err
	})
	if err != nil {
		t.Fatal(err)
	}
	commitAggregate(t, app, a, d, 100200)
	if totals(storedChunks(t, app))[0] != 150 {
		t.Fatal("pending chunk restored expired bytes")
	}
	if err := RebuildBlocks(app, a.session, 100200); err != nil {
		t.Fatal(err)
	}
	rows, e = readRecords[data.ActivityBlock](app, "activity_blocks", "1=1", nil)
	if e != nil || len(rows) != 1 {
		t.Fatal(rows, e)
	}
	if rows[0].ID != before.ID || rows[0].OriginalStartMS != 100000 || rows[0].StartMS != 100100 || rows[0].Sent != 150 || !rows[0].Clipped {
		t.Fatalf("crossing block lost anchor/totals: %#v", rows[0])
	}
}

func TestRemovedSessionCannotBeRecreatedByCapture(t *testing.T) {
	app, a, d := captureApp(t)
	a.packet(testPacket(100000, 40000), "network", testDestination())
	if _, err := app.DB().Delete("sessions", dbx.HashExp{"id": a.session}).Execute(); err != nil {
		t.Fatal(err)
	}
	chunks := a.snapshot(100050)
	if _, err := persistCapture(app, a.session, a.epoch, a.generation, chunks, d, nil, data.CaptureHealth{}); err == nil {
		t.Fatal("orphan flush succeeded")
	}
	if len(storedChunks(t, app)) != 0 {
		t.Fatal("orphan traffic saved")
	}
}
