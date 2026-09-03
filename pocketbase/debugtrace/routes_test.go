package debugtrace

import (
	"bufio"
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	_ "myapp/migrations"
)

func TestDisabledRuntimeRegistersNoTraceRoute(t *testing.T) {
	app, sessionID := traceTestApp(t)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	RegisterRoutes(router, app, nil)
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()
	mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/api/infrareveal/debug/sessions/"+sessionID+"/trace", nil))
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
}

func TestTraceRouteStreamsSessionAndTerminatesOnCancellation(t *testing.T) {
	app, sessionID := traceTestApp(t)
	hub := testHub(t, Config{RingEvents: 20, IngressBuffer: 20})
	hub.TryEmit(validEvent(sessionID, 1, time.Now()))
	hub.TryEmit(validEvent("another-session", 2, time.Now()))
	waitForNewest(t, hub, 2)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	RegisterRoutes(router, app, hub)
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(mux)
	defer server.Close()

	ctx, cancel := context.WithCancel(context.Background())
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/infrareveal/debug/sessions/"+sessionID+"/trace", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK || response.Header.Get("Content-Type") != "text/event-stream" || response.Header.Get("X-Accel-Buffering") != "no" {
		t.Fatalf("unexpected response: status=%d headers=%v", response.StatusCode, response.Header)
	}

	reader := bufio.NewReader(response.Body)
	var streamed strings.Builder
	for !strings.Contains(streamed.String(), "event: batch") || strings.Count(streamed.String(), "\n\n") < 2 {
		line, readErr := reader.ReadString('\n')
		if readErr != nil {
			t.Fatal(readErr)
		}
		streamed.WriteString(line)
	}
	if strings.Contains(streamed.String(), "another-session") || !strings.Contains(streamed.String(), sessionID) {
		t.Fatalf("stream was not session scoped: %s", streamed.String())
	}
	cancel()
	_ = response.Body.Close()

	deadline := time.Now().Add(500 * time.Millisecond)
	for time.Now().Before(deadline) {
		stats, statsErr := hub.Stats(context.Background())
		if statsErr == nil && stats.Subscribers == 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	stats, _ := hub.Stats(context.Background())
	t.Fatalf("request cancellation left %d subscriber(s)", stats.Subscribers)
}

func traceTestApp(t *testing.T) (*pocketbase.PocketBase, string) {
	t.Helper()
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	collection, err := app.FindCollectionByNameOrId("sessions")
	if err != nil {
		t.Fatal(err)
	}
	record := core.NewRecord(collection)
	record.Set("name", "Trace route test")
	if err := app.Save(record); err != nil {
		t.Fatal(err)
	}
	return app, record.Id
}
