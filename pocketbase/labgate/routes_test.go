package labgate

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase"
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"

	_ "myapp/migrations"
)

func TestControlRoutesAuthenticationOriginAndValidation(t *testing.T) {
	fixture := newRouteFixture(t)
	response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/status", "", "", "")
	if response.Code != http.StatusOK || strings.Contains(response.Body.String(), fixture.token) {
		t.Fatalf("public status = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/status", "", "https://unlisted.example", ""); response.Code != http.StatusForbidden || response.Header().Get("Access-Control-Allow-Origin") != "" {
		t.Fatalf("unlisted cross-origin public status = %d headers=%v", response.Code, response.Header())
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/status", "", "https://debug.example", ""); response.Code != http.StatusOK || response.Header().Get("Access-Control-Allow-Origin") != "https://debug.example" {
		t.Fatalf("listed cross-origin public status = %d headers=%v", response.Code, response.Header())
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/pending", "", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("missing auth = %d", response.Code)
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/pending", "wrong", "", ""); response.Code != http.StatusUnauthorized {
		t.Fatalf("bad auth = %d", response.Code)
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/pending", fixture.token, "https://evil.example", ""); response.Code != http.StatusForbidden {
		t.Fatalf("bad origin = %d", response.Code)
	}
	if response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/pending", fixture.token, "https://debug.example", ""); response.Code != http.StatusOK || response.Header().Get("Access-Control-Allow-Origin") != "https://debug.example" {
		t.Fatalf("valid request = %d headers=%v", response.Code, response.Header())
	}
	if response := fixture.request(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, "", `{"sessionId":"x"}`); response.Code != http.StatusUnsupportedMediaType {
		t.Fatalf("content type = %d", response.Code)
	}
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, `{"sessionId":"x","unknown":true}`); response.Code != http.StatusBadRequest {
		t.Fatalf("strict json = %d %s", response.Code, response.Body.String())
	}
	large := `{"sessionId":"` + strings.Repeat("x", maxControlBodyBytes) + `"}`
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, large); response.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("body limit = %d", response.Code)
	}
}

func TestControlRoutesArmPendingDecideAndReconcileStatus(t *testing.T) {
	fixture := newRouteFixture(t)
	body := `{"sessionId":"` + fixture.sessionID + `","mode":"flow","clientIps":["10.0.0.2"]}`
	response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, body)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"active"`) {
		t.Fatalf("arm = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, body); response.Code != http.StatusConflict {
		t.Fatalf("repeat arm = %d", response.Code)
	}
	if err := fixture.queue.Inject(context.Background(), tcpPacket(77, 50100)); err != nil {
		t.Fatal(err)
	}
	var decisionID string
	eventually(t, func() bool {
		response := fixture.request(http.MethodGet, "/api/infrareveal/lab-gate/pending", fixture.token, "", "")
		var payload struct {
			Decisions []struct {
				ID         string `json:"id"`
				QueuedAtMS int64  `json:"queuedAtMs"`
			} `json:"decisions"`
		}
		_ = json.Unmarshal(response.Body.Bytes(), &payload)
		if len(payload.Decisions) != 1 || payload.Decisions[0].QueuedAtMS <= 0 {
			return false
		}
		decisionID = payload.Decisions[0].ID
		return true
	})
	response = fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/decisions/"+decisionID, fixture.token, `{"verdict":"accept","actor":"test operator"}`)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"approved"`) {
		t.Fatalf("decision = %d %s", response.Code, response.Body.String())
	}
	if verdict, err := fixture.queue.WaitForVerdict(context.Background(), 77); err != nil || verdict != VerdictAccept {
		t.Fatalf("kernel verdict = %q %v", verdict, err)
	}
	response = fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/decisions/"+decisionID, fixture.token, `{"verdict":"accept"}`)
	if response.Code != http.StatusConflict || !strings.Contains(response.Body.String(), `"alreadyTerminal":true`) {
		t.Fatalf("idempotent response = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/decisions/missing", fixture.token, `{"verdict":"accept"}`); response.Code != http.StatusNotFound {
		t.Fatalf("unknown decision = %d", response.Code)
	}
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/disarm", fixture.token, `{}`); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"state":"off"`) {
		t.Fatalf("disarm = %d %s", response.Code, response.Body.String())
	}
}

func TestControlRoutesRejectInactiveSessionAndOutsideClient(t *testing.T) {
	fixture := newRouteFixture(t)
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, `{"sessionId":"missing","mode":"flow","clientIps":["10.0.0.2"]}`); response.Code != http.StatusConflict {
		t.Fatalf("inactive = %d", response.Code)
	}
	body := `{"sessionId":"` + fixture.sessionID + `","mode":"flow","clientIps":["192.168.1.2"]}`
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, body); response.Code != http.StatusBadRequest {
		t.Fatalf("subnet = %d", response.Code)
	}
}

func TestControlRoutesStrictArmAndAcceptNext(t *testing.T) {
	fixture := newRouteFixture(t)
	bad := `{"sessionId":"` + fixture.sessionID + `","mode":"strict","clientIps":["10.0.0.2"],"strict":{"protocol":"tcp","clientIp":"10.0.0.2","clientPort":0,"remoteIp":"1.1.1.1","remotePort":443}}`
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, bad); response.Code != http.StatusBadRequest {
		t.Fatalf("incomplete strict tuple = %d %s", response.Code, response.Body.String())
	}
	body := `{"sessionId":"` + fixture.sessionID + `","mode":"strict","clientIps":["10.0.0.2"],"strict":{"protocol":"tcp","clientIp":"10.0.0.2","clientPort":50100,"remoteIp":"1.1.1.1","remotePort":443}}`
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/arm", fixture.token, body); response.Code != http.StatusOK {
		t.Fatalf("strict arm = %d %s", response.Code, response.Body.String())
	}
	if response := fixture.jsonRequest(http.MethodPost, "/api/infrareveal/lab-gate/strict/accept-next", fixture.token, `{"count":2,"actor":"route test"}`); response.Code != http.StatusOK || !strings.Contains(response.Body.String(), `"strictAutoAccept":2`) {
		t.Fatalf("accept next = %d %s", response.Code, response.Body.String())
	}
	packet := tcpPacket(91, 50100)
	packet.QueueMode = ModeStrict
	packet.TCPFlags = 0x10
	if err := fixture.queue.Inject(context.Background(), packet); err != nil {
		t.Fatal(err)
	}
	verdictCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if verdict, err := fixture.queue.WaitForVerdict(verdictCtx, packet.ID); err != nil || verdict != VerdictAccept {
		t.Fatalf("strict step verdict = %q %v", verdict, err)
	}
}

type routeFixture struct {
	t                *testing.T
	mux              http.Handler
	controller       *Controller
	queue            *FakeQueue
	token, sessionID string
}

func newRouteFixture(t *testing.T) *routeFixture {
	t.Helper()
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	if err := app.Bootstrap(); err != nil {
		t.Fatal(err)
	}
	if err := app.RunAppMigrations(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.ResetBootstrapState() })
	collection, _ := app.FindCollectionByNameOrId("sessions")
	session := core.NewRecord(collection)
	session.Set("name", "Gate route")
	session.Set("active", true)
	session.Set("started_at", time.Now())
	if err := app.Save(session); err != nil {
		t.Fatal(err)
	}
	config := testConfig()
	queue := NewFakeQueue()
	controller, err := NewController(context.Background(), config, queue, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = controller.Close(ctx)
	})
	eventually(t, func() bool { status, _ := controller.Status(context.Background()); return status.ListenerReady })
	router, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	token := strings.Repeat("t", 40)
	RegisterControlRoutes(router, app, controller, ControlRouteConfig{Token: []byte(token), AllowedOrigins: []string{"https://debug.example"}, ClientSubnet: netip.MustParsePrefix("10.0.0.0/24")})
	mux, err := router.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	return &routeFixture{t: t, mux: mux, controller: controller, queue: queue, token: token, sessionID: session.Id}
}

func (fixture *routeFixture) jsonRequest(method, path, token, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response := httptest.NewRecorder()
	fixture.mux.ServeHTTP(response, request)
	return response
}

func (fixture *routeFixture) request(method, path, token, origin, body string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if origin != "" {
		request.Header.Set("Origin", origin)
	}
	response := httptest.NewRecorder()
	fixture.mux.ServeHTTP(response, request)
	return response
}
