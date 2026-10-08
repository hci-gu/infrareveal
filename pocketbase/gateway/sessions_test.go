package gateway

import (
	"context"
	"errors"
	"fmt"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"myapp/labgate"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestRegisteredSessionHooksOnlyPublishCommittedState(t *testing.T) {
	app := ephemeralTestApp(t)
	g := testRuntime(t, app)
	g.Register()
	original := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": "original", "active": true})
	if g.CurrentSessionID() != original.Id {
		t.Fatal("create hook did not select session")
	}
	rollback := errors.New("rollback")
	err := app.RunInTransaction(func(tx core.App) error {
		collection, _ := tx.FindCollectionByNameOrId("sessions")
		next := core.NewRecord(collection)
		next.Set("name", "rollback")
		next.Set("active", true)
		if err := tx.Save(next); err != nil {
			return err
		}
		if g.CurrentSessionID() != original.Id {
			t.Fatal("uncommitted session escaped transaction")
		}
		return rollback
	})
	if !errors.Is(err, rollback) || g.CurrentSessionID() != original.Id {
		t.Fatalf("rollback state: %s %v", g.CurrentSessionID(), err)
	}
	failure := app.OnRecordUpdateExecute("sessions").BindFunc(func(e *core.RecordEvent) error { return errors.New("save failed") })
	original.Set("active", false)
	if err := app.Save(original); err == nil {
		t.Fatal("expected failure")
	}
	if g.CurrentSessionID() != original.Id {
		t.Fatal("failed update changed installed session")
	}
	app.OnRecordUpdateExecute("sessions").Unbind(failure)
	if err := app.Save(original); err != nil {
		t.Fatal(err)
	}
	if g.CurrentSessionID() != "" || original.GetDateTime("ended_at").IsZero() {
		t.Fatal("session did not end")
	}
	other := testRuntime(t, app)
	if other.CurrentSessionID() != "" {
		t.Fatal("runtime session state is global")
	}
	if err := other.ensureDefaultActiveSession(); err != nil {
		t.Fatal(err)
	}
	if other.CurrentSessionID() == original.Id {
		t.Fatal("restart resumed ended session")
	}
}

func TestRegisteredSessionCompletionFlushesAuditOutsideTransaction(t *testing.T) {
	app := ephemeralTestApp(t)
	g := testRuntime(t, app)
	g.Register()
	g.audit = labgate.NewAuditWriter(app, 8)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	session := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": "audit", "active": true})
	err := app.RunInTransaction(func(tx core.App) error {
		rec, err := tx.FindRecordById("sessions", session.Id)
		if err != nil {
			return err
		}
		rec.Set("active", false)
		return tx.Save(rec)
	})
	if err != nil {
		t.Fatal(err)
	}
	stored, _ := app.FindRecordById("sessions", session.Id)
	if !stored.GetBool("gate_audit_complete") || stored.GetDateTime("ended_at").IsZero() || g.CurrentSessionID() != "" {
		t.Fatal("missing committed completion")
	}
}

func TestConstructionIsInertAndStartFailureClosesResources(t *testing.T) {
	app := ephemeralTestApp(t)
	g := testRuntime(t, app)
	g.Register()
	if g.gate != nil || g.observation != nil || g.traceHub != nil {
		t.Fatal("construction started resources")
	}
	app.OnRecordCreateExecute("sessions").BindFunc(func(e *core.RecordEvent) error { return errors.New("startup fixture failure") })
	if err := g.Start(); err == nil {
		t.Fatal("expected startup failure")
	}
	if !g.resourcesClosed || g.started {
		t.Fatal("partial startup did not unwind")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := g.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestBatchSessionUpdatesUseOneOuterLifecycleBoundary(t *testing.T) {
	app := ephemeralTestApp(t)
	g := testRuntime(t, app)
	g.Register()
	app.Settings().Batch.Enabled = true
	app.Settings().Batch.MaxRequests = 10
	collection, _ := app.FindCollectionByNameOrId("sessions")
	allow := ""
	collection.UpdateRule = &allow
	if err := app.Save(collection); err != nil {
		t.Fatal(err)
	}
	session := saveEphemeralFixture(t, app, "sessions", map[string]any{"name": "batch", "active": true})
	g.audit = labgate.NewAuditWriter(app, 8)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := g.Close(ctx); err != nil {
			t.Error(err)
		}
	})
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	router.BindFunc(g.guardMutation)
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	body := fmt.Sprintf(`{"requests":[{"method":"PATCH","url":"/api/collections/sessions/records/%s","body":{"name":"renamed"}},{"method":"PATCH","url":"/api/collections/sessions/records/%s","body":{"active":false}}]}`, session.Id, session.Id)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request := httptest.NewRequestWithContext(ctx, http.MethodPost, "/api/batch", strings.NewReader(body))
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != 200 {
		t.Fatalf("batch session update: %d %s", response.Code, response.Body.String())
	}
	stored, _ := app.FindRecordById("sessions", session.Id)
	if stored.GetBool("active") || stored.GetString("name") != "renamed" || g.CurrentSessionID() != "" || !stored.GetBool("gate_audit_complete") {
		t.Fatal("batch did not commit and finish its session")
	}
}
