package gateway

import (
	"bufio"
	"context"
	"fmt"
	"myapp/debugtrace"
	"myapp/testsupport"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
)

func TestDisabledRuntimeRegistersNoTraceRoute(t *testing.T) {
	app, sessionID := traceTestApp(t)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	registerTraceRoutes(router, app, nil)
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
	hub := traceTestHub(t)
	hub.TryEmit(traceTestEvent(sessionID, 1, time.Now()))
	hub.TryEmit(traceTestEvent("another-session", 2, time.Now()))
	waitTraceSequence(t, hub, 2)
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	registerTraceRoutes(router, app, hub)
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
	app := testsupport.App(t)
	record := testsupport.Save(t, app, "sessions", map[string]any{
		"name": "Trace route test",
	})
	return app, record.Id
}

func traceTestHub(t *testing.T) *debugtrace.Hub {
	hub, _ := debugtrace.NewRuntime(context.Background(), debugtrace.Config{Enabled: true, RingEvents: 20, IngressBuffer: 20, BatchInterval: 2 * time.Millisecond, Retention: time.Minute})
	t.Cleanup(hub.Close)
	return hub
}
func traceTestEvent(session string, index int, at time.Time) debugtrace.Event {
	return debugtrace.Event{ID: fmt.Sprint("event-", index), SessionID: session, TraceID: fmt.Sprint("trace-", index), Kind: debugtrace.KindFlow, Stage: debugtrace.StageConntrack, OccurredAtMs: at.UnixMilli(), Timing: debugtrace.TimingObserved}
}
func waitTraceSequence(t *testing.T, hub *debugtrace.Hub, sequence uint64) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		stats, err := hub.Stats(context.Background())
		if err == nil && stats.NewestSequence >= sequence {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("trace sequence not received")
}
