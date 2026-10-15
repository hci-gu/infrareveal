package observer

import (
	"context"
	"myapp/data"
	"sync/atomic"
	"testing"
	"time"
)

func TestIdleCoverageAndFinalDrainNeedNoStoredConnection(t *testing.T) {
	app, a, _ := captureApp(t)
	now := time.Now().UnixMilli() / 50 * 50
	var observed int64
	r := New(app, nil, Config{}, func() string { return a.session }, nil, func(d CommittedTraffic) { observed += d.Bytes })
	input := make(chan sourceEvent, 8)
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now), status: "complete"}
	p := testPacket(now+100, 40000)
	input <- sourceEvent{session: a.session, at: p.ObservedAt, packet: &p}
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now + 200), status: "heartbeat"}
	close(input)
	var lost atomic.Int64
	if err := r.consume(input, &lost); err != nil {
		t.Fatal(err)
	}
	chunks := storedChunks(t, app)
	if len(chunks) != 1 || !chunks[0].Sealed || totals(chunks)[0] != 150 || observed != 150 {
		t.Fatalf("final drain failed: %#v %d", chunks, observed)
	}
	rows, e := readRecords[data.CaptureInterval](app, "capture_intervals", "quality='complete'", nil)
	if e != nil || len(rows) != 1 || rows[0].StartMS != now || rows[0].EndMS != now+200 {
		t.Fatalf("independent idle coverage: %#v %v", rows, e)
	}
	session, _ := app.FindRecordById("sessions", a.session)
	s, _ := data.Decode[data.Session](session)
	if s.Capture.Running || s.Capture.ConfirmedMS != now+200 {
		t.Fatalf("shutdown health incorrect: %#v", s.Capture)
	}
}
func TestQueueLossIsPartialCoverageAndPersistsCounter(t *testing.T) {
	app, a, _ := captureApp(t)
	now := time.Now().UnixMilli()
	r := New(app, nil, Config{}, func() string { return a.session }, nil, nil)
	input := make(chan sourceEvent, 2)
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now), status: "complete"}
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now + 100), status: "heartbeat"}
	close(input)
	var lost atomic.Int64
	lost.Store(7)
	if err := r.consume(input, &lost); err != nil {
		t.Fatal(err)
	}
	rows, e := readRecords[data.CaptureInterval](app, "capture_intervals", "quality='partial'", nil)
	if e != nil || len(rows) != 1 || rows[0].Dropped != 7 {
		t.Fatalf("loss became known silence: %#v %v", rows, e)
	}
	session, _ := app.FindRecordById("sessions", a.session)
	s, _ := data.Decode[data.Session](session)
	if s.Capture.Dropped != 7 {
		t.Fatalf("wrong cumulative loss: %#v", s.Capture)
	}
}
func TestDisabledCaptureClosesAndReportsUnavailable(t *testing.T) {
	app, a, _ := captureApp(t)
	r := New(app, nil, Config{}, func() string { return a.session }, nil, nil)
	r.Start()
	time.Sleep(30 * time.Millisecond)
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := r.Close(ctx); err != nil {
		t.Fatal(err)
	}
	record, _ := app.FindRecordById("sessions", a.session)
	s, _ := data.Decode[data.Session](record)
	if s.Capture.Quality != "unavailable" || s.Capture.Running {
		t.Fatalf("disabled capture claimed completeness: %#v", s.Capture)
	}
}

func TestLossStaysPartialUntilSourceWatermarkPassesDroppedPacket(t *testing.T) {
	app, a, _ := captureApp(t)
	now := time.Now().UnixMilli()
	r := New(app, nil, Config{Packet: PacketActivityConfig{FlushInterval: 20 * time.Millisecond}}, func() string { return a.session }, nil, nil)
	r.lossAt.Store(now + 500)
	input := make(chan sourceEvent, 4)
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now), status: "complete"}
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now + 100), status: "heartbeat"}
	var lost atomic.Int64
	lost.Store(7)
	done := make(chan error, 1)
	go func() { done <- r.consume(input, &lost) }()
	waitFor := func(confirmed int64) {
		t.Helper()
		deadline := time.Now().Add(time.Second)
		for time.Now().Before(deadline) {
			record, err := app.FindRecordById("sessions", a.session)
			if err != nil {
				t.Fatal(err)
			}
			s, err := data.Decode[data.Session](record)
			if err == nil && s.Capture.Generation > 0 && s.Capture.ConfirmedMS >= confirmed {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
		t.Fatal("capture flush did not advance")
	}
	waitFor(now + 100)
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now + 500), status: "heartbeat"}
	waitFor(now + 500)
	close(input)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	rows, err := readRecords[data.CaptureInterval](app, "capture_intervals", "quality='partial'", nil)
	if err != nil || len(rows) != 1 || rows[0].EndMS != now+500 || rows[0].Dropped != 7 {
		t.Fatalf("queue backlog concealed later loss: %#v %v", rows, err)
	}
}
