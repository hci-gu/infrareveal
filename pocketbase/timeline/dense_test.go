package timeline

import (
	"fmt"
	"github.com/pocketbase/dbx"
	"myapp/data"
	"myapp/testsupport"
	"strings"
	"testing"
	"time"
)

func TestDenseWindowConservesCountersBeyondOldLimit(t *testing.T) {
	app := testsupport.App(t)
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: 100000, EndedMS: 400000, Revision: 1, Capture: data.CaptureHealth{Epoch: "one"}})
	// 30 clients * 4 bindings * 60 chunks = 7,200 facts. The old reader rejected it.
	_, err := app.DB().NewQuery(`WITH RECURSIVE n(value) AS (SELECT 0 UNION ALL SELECT value+1 FROM n WHERE value<7199)
 INSERT INTO traffic_chunks (id,session,client_id,service_key,start_ms,chunk_ms,bucket_ms,samples,sealed)
 SELECT printf('chunk%010d',value),{:session},printf('client%d',value%30),printf('service%d',(value/30)%4),100000+(value/120)*5000,5000,50,'[[0,10,20,5,15,1,2],[50,30,40,20,30,2,3]]',1 FROM n`).Bind(dbx.Params{"session": session.Id}).Execute()
	if err != nil {
		t.Fatal(err)
	}
	for _, compact := range []bool{false, true} {
		reader := New(app)
		q := Query{from: 100000, to: 400000, resolution: 1000, limit: 73, compact: compact}
		var totals [6]int64
		pages := 0
		for {
			page, err := reader.Window(session.Id, q)
			if err != nil {
				t.Fatal(err)
			}
			pages++
			if len(page.Series) > q.limit {
				t.Fatalf("unbounded page: %d", len(page.Series))
			}
			for _, c := range page.Series {
				for _, s := range c.Samples {
					for i := range totals {
						totals[i] += s[i+1]
					}
				}
			}
			if page.Complete {
				break
			}
			if page.NextCursor == "" {
				t.Fatal("missing continuation")
			}
			q.cursor = page.NextCursor
			if pages > 1000 {
				t.Fatal("pagination failed to advance")
			}
		}
		reader.Close()
		want := [6]int64{7200 * 40, 7200 * 60, 7200 * 25, 7200 * 45, 7200 * 3, 7200 * 5}
		if totals != want {
			t.Fatalf("compact %v: totals %v, want %v", compact, totals, want)
		}
		t.Logf("compact=%v pages=%d", compact, pages)
	}
}

func TestLargeRoutesPageIndependentlyWithoutSkipping(t *testing.T) {
	app := testsupport.App(t)
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: 1000, EndedMS: 10000, Revision: 1})
	for i := 0; i < 50; i++ {
		saveFact(t, app, "route_evidence", data.RouteEvidence{ID: data.NewID(), Session: session.Id, Kind: "path", AttemptID: fmt.Sprint(i), Revision: 1, AvailableMS: 2000 + int64(i), Hops: []data.Hop{{TTL: 1, Annotation: strings.Repeat("x", 50000)}}})
	}
	r := New(app)
	defer r.Close()
	q := Query{from: 1000, to: 10000, resolution: 50, limit: 1000}
	seen := map[string]bool{}
	pages := 0
	for {
		page, err := r.Window(session.Id, q)
		if err != nil {
			t.Fatal(err)
		}
		if len(page.Routes) > 16 {
			t.Fatalf("unbounded route decode: %d", len(page.Routes))
		}
		for _, route := range page.Routes {
			if seen[route.ID] {
				t.Fatal("route repeated")
			}
			seen[route.ID] = true
		}
		pages++
		if page.Complete {
			break
		}
		q.cursor = page.NextCursor
		if pages > 10 {
			t.Fatal("route pagination did not advance")
		}
	}
	if len(seen) != 50 || pages != 4 {
		t.Fatalf("got %d routes in %d pages", len(seen), pages)
	}
}

func TestReadSnapshotDoesNotBlockWriterAndPinsCorrection(t *testing.T) {
	app := testsupport.App(t)
	session := saveFact(t, app, "sessions", data.Session{ID: data.NewID(), StartedMS: 1000, EndedMS: 10000, Revision: 1})
	for i := 0; i < 3; i++ {
		saveFact(t, app, "traffic_chunks", data.TrafficChunk{ID: fmt.Sprintf("chunk%010d", i), Session: session.Id, StartMS: 1000 + int64(i)*1000, ChunkMS: 1000, BucketMS: 50, Samples: []data.Sample{{0, 10, 20}}})
	}
	reader := New(app)
	defer reader.Close()
	q := Query{from: 1000, to: 10000, resolution: 50, limit: 1}
	first, err := reader.Window(session.Id, q)
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() {
		_, err := app.DB().NewQuery(`UPDATE traffic_chunks SET samples='[[0,100,200]]' WHERE session={:s}`).Bind(dbx.Params{"s": session.Id}).Execute()
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dashboard snapshot blocked capture writer")
	}
	q.cursor = first.NextCursor
	next, err := reader.Window(session.Id, q)
	if err != nil {
		t.Fatal(err)
	}
	if next.Series[0].Samples[0][1] != 10 {
		t.Fatal("mixed corrected and original revisions")
	}
}
