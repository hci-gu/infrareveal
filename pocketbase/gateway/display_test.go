package gateway

import (
	"encoding/json"
	"fmt"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/pocketbase/pocketbase/apis"
	"myapp/displaymode"
	"myapp/observer"
	"myapp/testsupport"
)

func TestDisplayRoutesResolveTheRequestingDeviceAndApplyRuntimePolicy(t *testing.T) {
	app := testsupport.App(t)
	path := filepath.Join(t.TempDir(), "leases")
	if err := os.WriteFile(path, []byte(fmt.Sprintf("%d 02:00:00:00:00:01 10.0.0.50 laptop *\n", time.Now().Add(time.Hour).Unix())), 0600); err != nil {
		t.Fatal(err)
	}
	g := New(app, Config{Observation: observer.Config{LeasePath: path, Scope: observer.NewObservationScope("10.0.0.0/24", "10.0.0.1")}})
	r, err := apis.NewRouter(app)
	if err != nil {
		t.Fatal(err)
	}
	g.registerDisplayRoutes(r)
	handler, err := r.BuildMux()
	if err != nil {
		t.Fatal(err)
	}
	call := func(action, remote, forwarded, body string) *httptest.ResponseRecorder {
		t.Helper()
		req := httptest.NewRequest("POST", "/api/infrareveal/display-mode/"+action, strings.NewReader(body))
		req.RemoteAddr = remote
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Real-IP", forwarded)
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec
	}
	if got := call("start", "192.168.1.12:5000", "10.0.0.50", `{}`); got.Code != 403 {
		t.Fatalf("direct client spoofed proxy header: %d %s", got.Code, got.Body)
	}
	response := call("start", "127.0.0.1:5000", "10.0.0.50", `{}`)
	if response.Code != 200 {
		t.Fatal(response.Code, response.Body)
	}
	var role displaymode.Status
	if err := json.Unmarshal(response.Body.Bytes(), &role); err != nil {
		t.Fatal(err)
	}
	if !g.config.Observation.Scope.ExcludesClient("10.0.0.50", "02:00:00:00:00:01") || !g.config.Gate.ExcludedClient("10.0.0.50") {
		t.Fatal("role not shared with capture and gate")
	}
	body := fmt.Sprintf(`{"token":%q}`, role.Token)
	if response := call("renew", "10.0.0.50:5000", "", body); response.Code != 200 {
		t.Fatal(response.Code, response.Body)
	}
	if response := call("stop", "10.0.0.50:5000", "", body); response.Code != 200 {
		t.Fatal(response.Code, response.Body)
	}
	if g.config.Observation.Scope.ExcludesClient("10.0.0.50", "") {
		t.Fatal("stop not applied")
	}
	if response := call("renew", "10.0.0.50:5000", "", body); response.Code != 409 {
		t.Fatal("stopped role revived")
	}
}
