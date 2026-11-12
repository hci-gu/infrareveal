package observer

import (
	"context"
	"net/url"
	"strconv"
	"testing"
	"time"

	"myapp/data"
	"myapp/testsupport"
	"myapp/timeline"
)

func TestLiveLoadDrainsEveryOfferedPacketIntoClosedWindow(t *testing.T) {
	app := testsupport.App(t)
	start := time.Now().Add(-time.Second).UnixMilli()
	s := data.Session{ID: data.NewID(), StartedMS: start, RetainedFromMS: start, Active: true, Policy: DefaultPolicy()}
	if _, err := data.Write(app, "sessions", s); err != nil {
		t.Fatal(err)
	}
	meter := &TrafficLoadMeter{}
	r := NewTrafficLoad(app, s.ID, time.Now().Add(300*time.Millisecond), 2, 2, 2000, meter)
	r.Start()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := r.Wait(ctx); err != nil {
		t.Fatal(err)
	}
	reader := timeline.New(app)
	defer reader.Close()
	m, err := reader.Manifest(s.ID, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	q, err := timeline.ParseQuery(url.Values{"from": {strconv.FormatInt(start, 10)}, "to": {strconv.FormatInt(m.Capture.ConfirmedMS, 10)}, "resolution": {"50"}})
	if err != nil {
		t.Fatal(err)
	}
	window, err := reader.Window(s.ID, q)
	if err != nil {
		t.Fatal(err)
	}
	var packets, wire int64
	for _, c := range window.Series {
		for _, bin := range c.Samples {
			wire += bin[1] + bin[2]
			packets += bin[5] + bin[6]
		}
	}
	if !window.Complete || m.Capture.Dropped != 0 || packets == 0 || packets != meter.Packets.Load() || wire != meter.WireBytes.Load() {
		t.Fatalf("incomplete live capture: packets %d/%d, wire %d/%d, dropped %d", packets, meter.Packets.Load(), wire, meter.WireBytes.Load(), m.Capture.Dropped)
	}
}
