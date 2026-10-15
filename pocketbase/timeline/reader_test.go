package timeline

import (
	"errors"
	"fmt"
	"reflect"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/testsupport"
)

func saveFact(t *testing.T, app core.App, collection string, value any) *core.Record {
	t.Helper()
	record, err := data.Write(app, collection, value)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func query(t *testing.T, from, to int64, extra map[string]string) Query {
	t.Helper()
	values := map[string][]string{"from": {fmt.Sprint(from)}, "to": {fmt.Sprint(to)}}
	for key, value := range extra {
		values[key] = []string{value}
	}
	q, err := ParseQuery(values)
	if err != nil {
		t.Fatal(err)
	}
	return q
}

func TestWindowPaginationConservesBytesAndPinsLiveRevision(t *testing.T) {
	app := testsupport.App(t)
	const start int64 = 1700000000000
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: start, EndedMS: start + 10000, Revision: 7, Policy: data.Policy{BucketMS: 50}})
	destination := saveFact(t, app, "destinations", data.Destination{ID: data.NewID(), IP: "1.1.1.1", Version: "fixture", Precision: "unknown"})
	saveFact(t, app, "destinations", data.Destination{ID: data.NewID(), IP: "8.8.8.8", Version: "unused"})
	for i := 0; i < 3; i++ {
		saveFact(t, app, "traffic_chunks", data.TrafficChunk{ID: data.NewID(), Session: session.Id, CaptureEpoch: "capture", ClientID: fmt.Sprint(i), ServiceKey: "example.test", DestinationID: destination.Id, StartMS: start, BucketMS: 50, ChunkMS: 5000, Samples: []data.Sample{{0, 10, 20, 5, 10, 1, 2}, {50, 30, 40, 15, 20, 3, 4}}})
	}
	saveFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session.Id, StartMS: start, EndMS: start + 10000, Quality: "complete"})
	q := query(t, start, start+5000, map[string]string{"limit": "2", "resolution": "500"})
	reader := New(app)
	first, err := reader.Window(session.Id, q)
	if err != nil {
		t.Fatal(err)
	}
	if first.Complete || first.NextCursor == "" || len(first.Series) != 2 || len(first.Destinations) != 1 || len(first.Coverage) != 1 {
		t.Fatalf("bad first page: %+v", first)
	}
	q.cursor = first.NextCursor
	if err := data.BumpRevision(app, session.Id); err != nil {
		t.Fatal(err)
	}
	second, err := reader.Window(session.Id, q)
	if err != nil {
		t.Fatal(err)
	}
	if !second.Complete || second.NextCursor != "" || len(second.Series) != 1 || second.Revision != first.Revision {
		t.Fatalf("bad final page: %+v", second)
	}
	var sent, received int64
	for _, series := range append(first.Series, second.Series...) {
		if series.BucketMS != 500 || len(series.Samples) != 1 {
			t.Fatalf("resolution not applied: %+v", series)
		}
		sent += series.Samples[0][1]
		received += series.Samples[0][2]
	}
	if sent != 120 || received != 180 {
		t.Fatalf("pagination changed captured bytes: %d/%d", sent, received)
	}
	changed := q
	changed.to += 50
	if _, err := reader.Window(session.Id, changed); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("cursor accepted another window: %v", err)
	}
	reader.snapshots[0].at = time.Now().Add(-snapshotTTL)
	if _, err := reader.Window(session.Id, q); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("accepted expired snapshot: %v", err)
	}
	reader.snapshots[0].at = time.Now()
	current, err := app.FindRecordById("sessions", session.Id)
	if err != nil {
		t.Fatal(err)
	}
	current.Set("retained_from_ms", start+50)
	if err := app.Save(current); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Window(session.Id, q); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("snapshot restored pruned data: %v", err)
	}
}

func TestWindowEmptyCoverageBlockFilterAndRouteAnchors(t *testing.T) {
	app := testsupport.App(t)
	const start int64 = 1700000000000
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: start, EndedMS: start + 20000, RetainedFromMS: start + 1000, Revision: 1, Policy: data.Policy{BucketMS: 50}})
	block := saveFact(t, app, "activity_blocks", data.ActivityBlock{ID: data.NewID(), Session: session.Id, ClientID: "client", ServiceKey: "svt.se", StartMS: start + 2000, EndMS: start + 2050, Sent: 100})
	for _, service := range []string{"svt.se", "other.test"} {
		saveFact(t, app, "traffic_chunks", data.TrafficChunk{ID: data.NewID(), Session: session.Id, ClientID: "client", ServiceKey: service, StartMS: start, BucketMS: 50, ChunkMS: 5000, Samples: []data.Sample{{2000, 100, 0, 50, 0, 1, 0}}})
	}
	saveFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session.Id, StartMS: start, EndMS: start + 10000, Quality: "complete"})
	saveFact(t, app, "capture_intervals", data.CaptureInterval{ID: data.NewID(), Session: session.Id, StartMS: start + 10000, EndMS: start + 20000, Quality: "unavailable", Reason: "capture stopped"})
	for i, available := range []int64{start, start + 1000, start + 3000} {
		saveFact(t, app, "route_evidence", data.RouteEvidence{ID: data.NewID(), Session: session.Id, Kind: "path", NetworkEpoch: "network", BindingKey: "binding", AttemptID: fmt.Sprint(i), Revision: 1, AvailableMS: available, ValidUntilMS: start + 20000})
	}
	invalidation := saveFact(t, app, "route_evidence", data.RouteEvidence{ID: data.NewID(), Session: session.Id, Kind: "network_invalidated", NetworkEpoch: "network", AvailableMS: start + 1500})
	result, err := New(app).Window(session.Id, query(t, start, start+5000, map[string]string{"block": block.Id, "resolution": "500"}))
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Series) != 1 || result.Series[0].ServiceKey != "svt.se" || result.Series[0].BucketMS != 50 || len(result.Blocks) != 1 {
		t.Fatalf("block members incorrect: %+v", result)
	}
	if result.FromMS != start+2000 || result.ToMS != start+2050 || len(result.Routes) != 2 || result.Routes[1].ID != invalidation.Id {
		t.Fatalf("bounds or pre-window evidence missing: %+v", result)
	}
	empty, err := New(app).Window(session.Id, query(t, start+10000, start+20000, nil))
	if err != nil {
		t.Fatal(err)
	}
	if len(empty.Series) != 0 || len(empty.Coverage) != 1 || empty.Coverage[0].Quality != "unavailable" {
		t.Fatalf("zero traffic hid capture failure: %+v", empty)
	}
	if _, err := New(app).Block("another-session", block.Id); err == nil {
		t.Fatal("block leaked across sessions")
	}
}

func TestSamplesNeverMoveFutureCountsBeforeCursor(t *testing.T) {
	source := data.TrafficChunk{StartMS: 1000, BucketMS: 50, ChunkMS: 5000, Samples: []data.Sample{{0, 10, 20, 3, 4, 1, 2}, {50, 30, 40, 5, 6, 3, 4}, {500, 50, 60, 7, 8, 5, 6}}}
	for _, test := range []struct {
		cursor int64
		sent   int64
	}{{1049, 0}, {1050, 10}, {1099, 10}, {1100, 40}, {1550, 90}} {
		chunk := source
		chunk.Samples = visibleSamples(chunk, 1000, test.cursor)
		chunk = coarsen(chunk, 500, 1000, test.cursor)
		var sent int64
		for _, sample := range chunk.Samples {
			sent += sample[1]
		}
		if sent != test.sent || chunk.BucketMS != 50 {
			t.Fatalf("cursor %d: sent=%d bucket=%d", test.cursor, sent, chunk.BucketMS)
		}
	}
	coarse := coarsen(source, 500, 1000, 6000)
	if coarse.BucketMS != 500 || !reflect.DeepEqual(coarse.Samples, []data.Sample{{0, 40, 60, 8, 10, 4, 6}, {500, 50, 60, 7, 8, 5, 6}}) {
		t.Fatalf("coarsening changed columns: %+v", coarse)
	}
}

func TestManifestAndQueryBounds(t *testing.T) {
	app := testsupport.App(t)
	row := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: 1000, RetainedFromMS: 2000, EndedMS: 10000, Ephemeral: true, Revision: 4})
	manifest, err := New(app).Manifest(row.Id, time.UnixMilli(30000))
	if err != nil || manifest.StartedMS != 1000 || manifest.RetainedFromMS != 2000 || manifest.ServerMS != 30000 {
		t.Fatalf("manifest lost durable identity: %+v %v", manifest, err)
	}
	for _, values := range []map[string][]string{{}, {"from": {"0"}, "to": {"1800001"}}, {"from": {"5"}, "to": {"5"}}, {"from": {"0"}, "to": {"10"}, "limit": {"1001"}}, {"from": {"0"}, "to": {"10"}, "resolution": {"0"}}} {
		if _, err := ParseQuery(values); err == nil {
			t.Fatalf("accepted unbounded query: %v", values)
		}
	}
	q := query(t, 0, 10000, map[string]string{"cursor": "bogus"})
	if _, err := New(app).Window(row.Id, q); !errors.Is(err, ErrInvalidQuery) {
		t.Fatalf("bad cursor error: %v", err)
	}
}

func TestBlockPagesPinRevisionAndInvalidateOnClearOrRetention(t *testing.T) {
	app := testsupport.App(t)
	const start int64 = 1700000000000
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: start, EndedMS: start + 7200000, Revision: 3, Capture: data.CaptureHealth{Epoch: "capture-one"}})
	var last *core.Record
	for i := 0; i < 3; i++ {
		last = saveFact(t, app, "activity_blocks", data.ActivityBlock{ID: data.NewID(), Session: session.Id, StartMS: start + int64(i)*3000000, EndMS: start + int64(i)*3000000 + 50, Sent: int64(i + 1)})
	}
	q, err := ParseBlockQuery(map[string][]string{"from": {fmt.Sprint(start)}, "to": {fmt.Sprint(start + 7200000)}, "limit": {"2"}})
	if err != nil {
		t.Fatal(err)
	}
	reader := New(app)
	first, err := reader.Blocks(session.Id, q)
	if err != nil || len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first block page: %+v %v", first, err)
	}
	last.Set("sent", 999)
	if err := app.Save(last); err != nil {
		t.Fatal(err)
	}
	if err := data.BumpRevision(app, session.Id); err != nil {
		t.Fatal(err)
	}
	q.cursor = first.NextCursor
	second, err := reader.Blocks(session.Id, q)
	if err != nil || len(second.Items) != 1 || second.Items[0].Sent != 3 || second.Revision != first.Revision || second.NextCursor != "" {
		t.Fatalf("live flush changed an in-flight block snapshot: %+v %v", second, err)
	}
	if _, err := reader.Window(session.Id, q); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("block cursor reused for map data: %v", err)
	}
	// Same-bin clear cannot advance the retained boundary, so its new capture
	// epoch must invalidate a cached page even when the old edge is unchanged.
	if _, err := app.DB().NewQuery(`UPDATE sessions SET capture='{"epoch":"capture-two"}' WHERE id={:s}`).Bind(dbx.Params{"s": session.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Blocks(session.Id, q); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("clear returned old cached block data: %v", err)
	}
	q.cursor = ""
	first, err = reader.Blocks(session.Id, q)
	if err != nil {
		t.Fatal(err)
	}
	q.cursor = first.NextCursor
	if _, err := app.DB().NewQuery("UPDATE sessions SET retained_from_ms={:from} WHERE id={:s}").Bind(dbx.Params{"s": session.Id, "from": start + 50}).Execute(); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.Blocks(session.Id, q); !errors.Is(err, ErrRevisionChanged) {
		t.Fatalf("retention returned old cached block data: %v", err)
	}
}

func TestBlockSnapshotRejectsMoreThanFourThousandSummaries(t *testing.T) {
	app := testsupport.App(t)
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: 1000, EndedMS: 100000})
	if _, err := app.DB().NewQuery("WITH RECURSIVE n(value) AS (SELECT 1 UNION ALL SELECT value+1 FROM n WHERE value<=4000) INSERT INTO activity_blocks (id,session,start_ms,end_ms) SELECT printf('block%010d',value),{:s},1000+value,1050+value FROM n").Bind(dbx.Params{"s": session.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	q, err := ParseBlockQuery(map[string][]string{"from": {"1000"}, "to": {"100000"}, "limit": {"1000"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := New(app).Blocks(session.Id, q); !errors.Is(err, ErrWindowTooLarge) {
		t.Fatalf("unbounded block snapshot accepted: %v", err)
	}
}

// Dense fixture: one minute, fifty destination bindings, all 50 ms bins active.
// Includes both HTTP-page projections so changes to the snapshot path are visible.
func BenchmarkMapWindow(b *testing.B) {
	app := testsupport.App(b)
	const start int64 = 1700000000000
	sessionID := data.NewID()
	samples := make([]data.Sample, 100)
	for i := range samples {
		samples[i] = data.Sample{int64(i) * 50, 60, 120, 20, 80, 1, 2}
	}
	err := app.RunInTransaction(func(tx core.App) error {
		if _, err := data.Write(tx, "sessions", data.Session{ID: sessionID, StartedMS: start, EndedMS: start + 60000, Revision: 1, Policy: data.Policy{BucketMS: 50}}); err != nil {
			return err
		}
		for binding := 0; binding < 50; binding++ {
			for second := 0; second < 60; second += 5 {
				_, err := data.Write(tx, "traffic_chunks", data.TrafficChunk{ID: data.NewID(), Session: sessionID, ClientID: "client", ServiceKey: fmt.Sprintf("service-%d.test", binding), StartMS: start + int64(second)*1000, BucketMS: 50, ChunkMS: 5000, Samples: samples})
				if err != nil {
					return err
				}
			}
		}
		return nil
	})
	if err != nil {
		b.Fatal(err)
	}
	for _, resolution := range []int64{50, 1000} {
		b.Run(fmt.Sprintf("%dms", resolution), func(b *testing.B) {
			reader := New(app)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				q := Query{from: start, to: start + 60000, resolution: resolution, limit: 500}
				window, err := reader.Window(sessionID, q)
				if err != nil {
					b.Fatal(err)
				}
				if window.NextCursor != "" {
					q.cursor = window.NextCursor
					if _, err = reader.Window(sessionID, q); err != nil {
						b.Fatal(err)
					}
				}
			}
		})
	}
}
