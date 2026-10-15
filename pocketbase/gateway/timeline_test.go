package gateway

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"myapp/data"
	"myapp/observer"
	"myapp/testsupport"
)

func gatewayHTTP(t *testing.T) (*pocketbase.PocketBase, *Runtime, http.Handler) {
	t.Helper()
	app := testsupport.App(t)
	g := testRuntime(t, app)
	g.Register()
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	router.BindFunc(g.guardMutation)
	registerSessionTimelineRoutes(router, app)
	g.registerSessionControls(router)
	g.registerDemoRoutes(router)
	handler, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return app, g, handler
}

func requestJSON(t *testing.T, handler http.Handler, method, path, body, token string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, strings.NewReader(body))
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", token)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}

func TestSessionControlAPITransitionsAtomically(t *testing.T) {
	app, g, handler := gatewayHTTP(t)
	firstResponse := requestJSON(t, handler, http.MethodPost, "/api/infrareveal/sessions", `{"name":"first"}`, "")
	if firstResponse.Code != http.StatusCreated {
		t.Fatalf("start: %d %s", firstResponse.Code, firstResponse.Body.String())
	}
	var first data.Session
	if err := json.Unmarshal(firstResponse.Body.Bytes(), &first); err != nil {
		t.Fatal(err)
	}
	invalid := requestJSON(t, handler, http.MethodPost, "/api/infrareveal/sessions", `{"name":"invalid","retention_minutes":2000}`, "")
	if invalid.Code != 400 || g.CurrentSessionID() != first.ID {
		t.Fatalf("invalid start closed old session: %d %s", invalid.Code, invalid.Body.String())
	}
	stored, _ := app.FindRecordById("sessions", first.ID)
	if !stored.GetBool("active") {
		t.Fatal("failed start changed committed lifecycle")
	}
	secondResponse := requestJSON(t, handler, http.MethodPost, "/api/infrareveal/sessions", `{"name":"second","ephemeral":true,"retention_minutes":5}`, "")
	if secondResponse.Code != 201 {
		t.Fatalf("replace: %d %s", secondResponse.Code, secondResponse.Body.String())
	}
	var second data.Session
	if err := json.Unmarshal(secondResponse.Body.Bytes(), &second); err != nil {
		t.Fatal(err)
	}
	stored, _ = app.FindRecordById("sessions", first.ID)
	if stored.GetBool("active") || stored.GetInt64("ended_ms") == 0 || stored.GetInt64("started_ms") != first.StartedMS || g.CurrentSessionID() != second.ID {
		t.Fatal("start did not atomically replace active recording")
	}
	stored.Set("active", true)
	if err := app.Save(stored); err == nil {
		t.Fatal("reopened an ended recording")
	}
	ended := requestJSON(t, handler, http.MethodPost, "/api/infrareveal/sessions/"+second.ID+"/end", `{}`, "")
	if ended.Code != 200 || g.CurrentSessionID() != "" {
		t.Fatalf("end: %d %s", ended.Code, ended.Body.String())
	}
	renamed := requestJSON(t, handler, http.MethodPatch, "/api/infrareveal/sessions/"+first.ID, `{"name":"saved"}`, "")
	if renamed.Code != 200 {
		t.Fatalf("rename: %d %s", renamed.Code, renamed.Body.String())
	}
	list := requestJSON(t, handler, http.MethodGet, "/api/infrareveal/sessions", "", "")
	var listing struct {
		Items []data.Session `json:"items"`
	}
	if err := json.Unmarshal(list.Body.Bytes(), &listing); err != nil || len(listing.Items) != 2 {
		t.Fatalf("session list: %s %v", list.Body.String(), err)
	}
}

func TestMapHTTPReturnsTypedProductsAndNoCollectorAPI(t *testing.T) {
	app, _, handler := gatewayHTTP(t)
	const start int64 = 1700000000000
	session := testsupport.Save(t, app, "sessions", map[string]any{"started_ms": start, "ended_ms": start + 10000, "policy": observer.DefaultPolicy()})
	prefix := "/api/infrareveal/sessions/" + session.Id
	manifest := requestJSON(t, handler, http.MethodGet, prefix+"/manifest", "", "")
	var value data.Manifest
	if err := json.Unmarshal(manifest.Body.Bytes(), &value); err != nil || value.ID != session.Id || value.StartedMS != start || value.Policy.BucketMS != 50 {
		t.Fatalf("manifest: %s %v", manifest.Body.String(), err)
	}
	path := fmt.Sprintf("%s/map?from=%d&to=%d", prefix, start, start+10000)
	response := requestJSON(t, handler, http.MethodGet, path, "", "")
	if response.Code != 200 {
		t.Fatalf("map: %d %s", response.Code, response.Body.String())
	}
	var result map[string]any
	if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"series", "coverage", "blocks", "destinations", "routes"} {
		if values, ok := result[name].([]any); !ok || len(values) != 0 {
			t.Fatalf("empty %s must be []: %s", name, response.Body.String())
		}
	}
	invalid := requestJSON(t, handler, http.MethodGet, prefix+"/map?from=0&to=9999999999", "", "")
	if invalid.Code != 400 {
		t.Fatalf("unbounded request: %d", invalid.Code)
	}
	if response := requestJSON(t, handler, http.MethodGet, prefix+"/window?from=0&to=1000", "", ""); response.Code != 404 {
		t.Fatal("old collector window endpoint remains")
	}
	if response := requestJSON(t, handler, http.MethodGet, "/api/collections/traffic_chunks/records", "", ""); response.Code == 200 {
		t.Fatal("raw core collection is public")
	}
}

func TestBlockBrowserAcceptsLongRecordingRangesButKeepsPageBounds(t *testing.T) {
	app, _, handler := gatewayHTTP(t)
	const start = int64(1700000000000)
	session := testsupport.Save(t, app, "sessions", map[string]any{"started_ms": start, "ended_ms": start + 7200000})
	for _, offset := range []int64{0, 3600000, 7000000} {
		testsupport.Save(t, app, "activity_blocks", map[string]any{"session": session.Id, "start_ms": start + offset, "end_ms": start + offset + 50, "active_ms": 50})
	}
	prefix := fmt.Sprintf("/api/infrareveal/sessions/%s/blocks?from=%d&to=%d", session.Id, start, start+7200000)
	response := requestJSON(t, handler, http.MethodGet, prefix+"&limit=1", "", "")
	var page data.BlockPage
	if err := json.Unmarshal(response.Body.Bytes(), &page); response.Code != 200 || err != nil || len(page.Items) != 1 || page.NextCursor == "" {
		t.Fatalf("long block range failed: %d %s %v", response.Code, response.Body.String(), err)
	}
	if response := requestJSON(t, handler, http.MethodGet, prefix+"&limit=1001", "", ""); response.Code != 400 {
		t.Fatal("long range bypassed the page limit")
	}
}

func TestSessionEndImmediatelyFinalizesBlocks(t *testing.T) {
	app, _, handler := gatewayHTTP(t)
	start := time.Now().Add(-time.Second).UnixMilli() / 50 * 50
	session := testsupport.Save(t, app, "sessions", map[string]any{"active": true, "started_ms": start})
	testsupport.Save(t, app, "traffic_chunks", map[string]any{"session": session.Id, "client_id": "client", "service_key": "svt.se", "start_ms": start, "bucket_ms": 50, "chunk_ms": 5000, "sealed": true, "samples": []data.Sample{{0, 150, 0, 90, 0, 1}}})
	if err := observer.RebuildBlocks(app, session.Id, time.Now().UnixMilli()); err != nil {
		t.Fatal(err)
	}
	response := requestJSON(t, handler, http.MethodPost, "/api/infrareveal/sessions/"+session.Id+"/end", `{}`, "")
	if response.Code != 200 {
		t.Fatalf("end: %d %s", response.Code, response.Body.String())
	}
	blocks, err := app.FindAllRecords("activity_blocks")
	if err != nil || len(blocks) != 1 || blocks[0].GetBool("provisional") || blocks[0].GetInt64("sent") != 150 {
		t.Fatalf("closed session kept mutable blocks: %v %v", blocks, err)
	}
}

func TestDiagnosticsAreExplicitlyOptionalAndAuthenticated(t *testing.T) {
	app, g, handler := gatewayHTTP(t)
	collection, err := app.FindCollectionByNameOrId(core.CollectionNameSuperusers)
	if err != nil {
		t.Fatal(err)
	}
	admin := core.NewRecord(collection)
	admin.Set("email", "operator@example.test")
	admin.SetPassword("fixture-password-123")
	if err := app.Save(admin); err != nil {
		t.Fatal(err)
	}
	token, err := admin.NewAuthToken()
	if err != nil {
		t.Fatal(err)
	}
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "core"})
	path := "/api/infrareveal/sessions/" + session.Id + "/diagnostics/dns"
	if response := requestJSON(t, handler, http.MethodGet, path, "", ""); response.Code != 401 {
		t.Fatalf("raw diagnostics should require auth: %d %s", response.Code, response.Body.String())
	}
	if response := requestJSON(t, handler, http.MethodGet, path, "", token); response.Code != 404 {
		t.Fatalf("core should disclose unavailable diagnostics: %d %s", response.Code, response.Body.String())
	}
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	g.config.Diagnostics = true
	diagnosticSession := testsupport.Save(t, app, "sessions", map[string]any{"name": "diagnostic"})
	if response := requestJSON(t, handler, http.MethodGet, path, "", token); response.Code != 404 {
		t.Fatal("installing diagnostics changed old recording profile")
	}
	const from, to int64 = 1700000000000, 1700000001000
	stamp := func(ms int64) string { return time.UnixMilli(ms).UTC().Format("2006-01-02 15:04:05.000Z") }
	for kind, collection := range map[string]string{"dns": "dns_queries", "flows": "flow_diagnostics", "gate": "gate_events"} {
		t.Run(kind, func(t *testing.T) {
			for i, at := range []int64{from - 1, from, to - 1, to} {
				fields := map[string]any{"session": diagnosticSession.Id}
				switch kind {
				case "dns":
					fields["observed_ms"] = at
				case "flows":
					fields["start_ms"], fields["last_ms"] = at, at
					if i == 1 {
						fields["start_ms"] = from - 100
					}
				case "gate":
					fields["decision_id"], fields["queued_at"], fields["decided_at"] = fmt.Sprint(i), stamp(at), stamp(at)
					if i == 1 {
						fields["queued_at"] = stamp(from - 100)
					}
					if i == 2 {
						fields["decided_at"] = ""
					}
				}
				testsupport.Save(t, app, collection, fields)
			}
			// Matching timestamps in another session must never leak into this window.
			testsupport.Save(t, app, collection, map[string]any{"session": session.Id, "observed_ms": from, "start_ms": from, "last_ms": from, "queued_at": stamp(from), "decided_at": stamp(from)})
			path := fmt.Sprintf("/api/infrareveal/sessions/%s/diagnostics/%s", diagnosticSession.Id, kind)
			for _, query := range []string{"", "?from=20&to=10", "?from=0&to=1800001"} {
				if response := requestJSON(t, handler, http.MethodGet, path+query, "", token); response.Code != 400 {
					t.Fatalf("unbounded diagnostic request accepted: %d %s", response.Code, response.Body.String())
				}
			}
			response := requestJSON(t, handler, http.MethodGet, fmt.Sprintf("%s?from=%d&to=%d", path, from, to), "", token)
			var result struct {
				Items []map[string]any `json:"items"`
				More  bool             `json:"more"`
			}
			if err := json.Unmarshal(response.Body.Bytes(), &result); err != nil || response.Code != 200 || len(result.Items) != 2 || result.More {
				t.Fatalf("diagnostic window: %s %v", response.Body.String(), err)
			}
		})
	}
}

func TestRevisionStreamCoalescesSQLUpdatesAndCancels(t *testing.T) {
	app, _, handler := gatewayHTTP(t)
	session := testsupport.Save(t, app, "sessions", map[string]any{"name": "stream"})
	server := httptest.NewServer(handler)
	defer server.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+"/api/infrareveal/sessions/"+session.Id+"/revisions", nil)
	response, err := server.Client().Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 || response.Header.Get("Content-Type") != "text/event-stream" {
		t.Fatalf("not an SSE stream: %d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	read := func() string {
		t.Helper()
		var result strings.Builder
		for {
			line, err := reader.ReadString('\n')
			if err != nil {
				t.Fatal(err)
			}
			result.WriteString(line)
			if line == "\n" {
				return result.String()
			}
		}
	}
	if initial := read(); !strings.Contains(initial, "event: revision") || !strings.Contains(initial, `"revision":1`) {
		t.Fatalf("missing initial revision: %s", initial)
	}
	for i := 0; i < 3; i++ {
		if err := data.BumpRevision(app, session.Id); err != nil {
			t.Fatal(err)
		}
	}
	if update := read(); !strings.Contains(update, `"revision":4`) {
		t.Fatalf("SQL revisions did not coalesce: %s", update)
	}
	cancel()
	if _, err := reader.ReadString('\n'); err == nil {
		t.Fatal("cancelled stream did not end")
	}
}
