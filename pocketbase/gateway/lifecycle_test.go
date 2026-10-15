package gateway

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"testing"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/observer"
	"myapp/testsupport"
	"myapp/timeline"
)

func TestSessionEditPreservesConcurrentCaptureRevision(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	stale := testsupport.Save(t, app, "sessions", map[string]any{"name": "before", "active": true})
	originalStart := stale.GetInt64("started_ms")
	if _, err := app.DB().NewQuery(`UPDATE sessions SET revision=20, network_epoch='new-epoch', capture='{"quality":"partial","dropped":3}', retained_from_ms=started_ms+50, block_watermark_ms=started_ms+100 WHERE id={:id}`).Bind(dbx.Params{"id": stale.Id}).Execute(); err != nil {
		t.Fatal(err)
	}
	stale.Set("name", "after")
	stale.Set("started_ms", 1)
	if err := app.Save(stale); err != nil {
		t.Fatal(err)
	}
	current, err := app.FindRecordById("sessions", stale.Id)
	if err != nil {
		t.Fatal(err)
	}
	if current.GetInt64("revision") != 21 || current.GetString("network_epoch") != "new-epoch" || current.GetInt64("started_ms") != originalStart || current.GetInt64("retained_from_ms") != originalStart+50 || current.GetInt64("block_watermark_ms") != originalStart+100 {
		t.Fatalf("stale session edit rewound capture state: %v", current.PublicExport())
	}
	var capture map[string]any
	if err := current.UnmarshalJSONField("capture", &capture); err != nil || capture["quality"] != "partial" {
		t.Fatalf("capture health lost: %v %v", capture, err)
	}
}

func TestInitialAndFreshClearBinsRemainVisible(t *testing.T) {
	for _, clearFirst := range []bool{false, true} {
		t.Run(map[bool]string{false: "initial", true: "clear"}[clearFirst], func(t *testing.T) {
			app := testsupport.App(t)
			g := testRuntime(t, app)
			g.Register()
			session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "started_ms": 100037})
			if session.GetInt64("started_ms") != 100000 || session.GetInt64("retained_from_ms") != 100000 {
				t.Fatal("session start discarded its crossing source bin")
			}
			if clearFirst {
				if _, err := g.Clear(context.Background()); err != nil {
					t.Fatal(err)
				}
				session, _ = app.FindRecordById("sessions", session.Id)
			}
			floor := session.GetInt64("retained_from_ms")
			if floor%50 != 0 {
				t.Fatalf("edge cuts a source bin: %d", floor)
			}
			start := floor / 5000 * 5000
			testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "start_ms": start, "bucket_ms": 50, "chunk_ms": 5000, "samples": []data.Sample{{floor - start, 150, 0, 90, 0, 1}}})
			// Pin a complete fixture end rather than depending on a wall-clock
			// sleep to finish the current source bin.
			if _, err := app.DB().NewQuery("UPDATE sessions SET active=0, ended_ms={:end} WHERE id={:s}").Bind(dbx.Params{"s": session.Id, "end": floor + 50}).Execute(); err != nil {
				t.Fatal(err)
			}
			query, err := timeline.ParseQuery(map[string][]string{"from": {fmt.Sprint(floor)}, "to": {fmt.Sprint(floor + 50)}})
			if err != nil {
				t.Fatal(err)
			}
			window, err := timeline.New(app).Window(session.Id, query)
			if err != nil || len(window.Series) != 1 || len(window.Series[0].Samples) != 1 || window.Series[0].Samples[0][1] != 150 {
				t.Fatalf("first accepted bin disappeared: %+v %v", window, err)
			}
		})
	}
}

func TestRenameDoesNotAdvanceRetentionWithoutPruningPrefixes(t *testing.T) {
	app := testsupport.App(t)
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "ephemeral": true, "started_ms": 100000, "retained_from_ms": 100000, "retention_minutes": 1, "policy": observer.DefaultPolicy()})
	g := testRuntime(t, app)
	g.Register()
	session.Set("name", "renamed")
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	current, err := app.FindRecordById("sessions", session.Id)
	if err != nil || current.GetInt64("retained_from_ms") != 100000 {
		t.Fatal("rename advanced retention without clipping stored prefix counters", err)
	}
}

func TestRawSessionCRUDAndBatchDrainCaptureBeforeMutation(t *testing.T) {
	app, g, handler := gatewayHTTP(t)
	app.Settings().Batch.Enabled, app.Settings().Batch.MaxRequests = true, 10
	collection, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(collection)
	admin.Set("email", "lifecycle@example.test")
	admin.SetPassword("fixture-password-123")
	if err := app.Save(admin); err != nil {
		t.Fatal(err)
	}
	token, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true})
	testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "start_ms": session.GetInt64("started_ms"), "bucket_ms": 50, "chunk_ms": 5000, "sealed": true, "samples": []data.Sample{{0, 150, 0, 90, 0, 1}}})
	config := g.config.Observation
	config.Packet.Enabled, config.Packet.FlushInterval = false, 5*time.Millisecond
	config.DNSLogPath, config.ConntrackPath, config.LeasePath = "", "", ""
	g.observation = observer.New(app, nil, config, g.CurrentSessionID, nil, nil)
	epochs := make(chan string, 16)
	app.OnRecordAfterCreateSuccess("capture_intervals").BindFunc(func(e *core.RecordEvent) error {
		select {
		case epochs <- e.Record.GetString("capture_epoch"):
		default:
		}
		return e.Next()
	})
	g.observation.Start()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	nextEpoch := func(previous string) string {
		t.Helper()
		deadline := time.After(time.Second)
		for {
			select {
			case epoch := <-epochs:
				if epoch != previous {
					return epoch
				}
			case <-deadline:
				t.Fatal("raw session mutation did not drain and restart capture")
			}
		}
	}
	previous := nextEpoch("")
	sessions, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"sessions", sessions.Id, "batch"} {
		path, method, body := "/api/collections/"+name+"/records/"+session.Id, http.MethodPatch, `{"name":"renamed"}`
		if name == "batch" {
			path, method = "/api/batch", http.MethodPost
			body = fmt.Sprintf(`{"requests":[{"method":"PATCH","url":"/api/collections/sessions/records/%s","body":{"name":"batch renamed"}}]}`, session.Id)
		}
		response := requestJSON(t, handler, method, path, body, token)
		if response.Code != 200 {
			t.Fatalf("%s: %d %s", name, response.Code, response.Body.String())
		}
		previous = nextEpoch(previous)
		rows, err := data.ReadTraffic(app.DB().Select("*").From("traffic_chunks"))
		if err != nil || len(rows) != 1 || rows[0].Samples[0][1] != 150 {
			t.Fatalf("%s changed accepted traffic: %+v %v", name, rows, err)
		}
	}
}

func TestSessionDeletionRollsBackWithItsChildren(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true})
	child := testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id})
	rollback := errors.New("fixture rollback")
	err := app.RunInTransaction(func(tx core.App) error {
		if err := tx.Delete(session); err != nil {
			return err
		}
		if g.CurrentSessionID() != session.Id {
			t.Fatal("deletion published before commit")
		}
		return rollback
	})
	if !errors.Is(err, rollback) {
		t.Fatal(err)
	}
	if _, err := app.FindRecordById("traffic_chunks", child.Id); err != nil {
		t.Fatal("rollback lost child", err)
	}
	if _, err := app.FindRecordById("sessions", session.Id); err != nil || g.CurrentSessionID() != session.Id {
		t.Fatal("rollback lost active identity", err)
	}
}

func TestClearJoinsAcceptedCaptureBeforeDeletingAndStartsFreshEpoch(t *testing.T) {
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "clear race", "active": true})
	config := g.config.Observation
	config.Packet.Enabled = false
	config.Packet.FlushInterval = 10 * time.Millisecond
	config.DNSLogPath = ""
	config.ConntrackPath = ""
	config.LeasePath = ""
	g.observation = observer.New(app, nil, config, g.CurrentSessionID, nil, nil)
	entered, release, newEpoch := make(chan struct{}), make(chan struct{}), make(chan struct{}, 1)
	var once, releaseOnce sync.Once
	var oldEpoch string
	app.OnRecordCreate("capture_intervals").BindFunc(func(e *core.RecordEvent) error {
		once.Do(func() { oldEpoch = e.Record.GetString("capture_epoch"); close(entered); <-release })
		return e.Next()
	})
	app.OnRecordAfterCreateSuccess("capture_intervals").BindFunc(func(e *core.RecordEvent) error {
		if e.Record.GetString("capture_epoch") != oldEpoch {
			select {
			case newEpoch <- struct{}{}:
			default:
			}
		}
		return e.Next()
	})
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	g.observation.Start()
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("capture never reached persistence")
	}
	cleared := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := g.Clear(ctx)
		cleared <- err
	}()
	select {
	case err := <-cleared:
		t.Fatalf("clear acknowledged a still-running writer: %v", err)
	case <-time.After(30 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	if err := <-cleared; err != nil {
		t.Fatal(err)
	}
	select {
	case <-newEpoch:
	case <-time.After(time.Second):
		t.Fatal("capture did not restart")
	}
	rows, err := app.FindRecordsByFilter("capture_intervals", "capture_epoch={:epoch}", "", 0, 0, dbx.Params{"epoch": oldEpoch})
	if err != nil || len(rows) != 0 {
		t.Fatalf("old capture returned after clear: %v %v", rows, err)
	}
	if g.CurrentSessionID() != session.Id {
		t.Fatal("clear changed session identity")
	}
}
