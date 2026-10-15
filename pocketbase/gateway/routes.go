package gateway

import (
	"github.com/pocketbase/pocketbase/apis"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/labgate"
	"net/http"
	"os"
	"strings"
)

func (g *Runtime) registerRoutes(r *router.Router[*core.RequestEvent]) {
	r.BindFunc(g.guardMutation)
	registerSessionTimelineRoutes(r, g.app)
	g.registerSessionControls(r)
	g.registerDemoRoutes(r)
	registerTraceRoutes(r, g.app, g.traceHub)
	labgate.RegisterControlRoutes(r, g.app, g.gate, labgate.ControlRouteConfig{Token: g.controlToken, AllowedOrigins: g.config.Gate.AllowedOrigins, ClientSubnet: g.config.ClientSubnet})
	r.POST("/api/infrareveal/clear-observations", func(e *core.RequestEvent) error {
		result, err := g.Clear(e.Request.Context())
		if err != nil {
			return e.JSON(http.StatusInternalServerError, map[string]string{"error": err.Error()})
		}
		return e.JSON(http.StatusOK, result)
	})
	r.GET("/{path...}", apis.Static(os.DirFS("./pb_public"), false))
	r.GET("/api/infrareveal/routes/status", func(e *core.RequestEvent) error { return e.JSON(http.StatusOK, g.routes.Status()) })
	r.POST("/api/infrareveal/routes/measure", func(e *core.RequestEvent) error {
		var request struct {
			ChunkID string `json:"chunk_id"`
		}
		if err := e.BindBody(&request); err != nil {
			return e.BadRequestError("Invalid request", err)
		}
		if err := g.routes.Measure(e.Request.Context(), request.ChunkID); err != nil {
			return e.BadRequestError(err.Error(), nil)
		}
		return e.JSON(http.StatusAccepted, map[string]bool{"accepted": true})
	})
}

// PocketBase batch requests perform recursive CRUD inside one transaction. Guard
// the outer HTTP request once, never lock from a nested record/transaction hook.
func (g *Runtime) guardMutation(e *core.RequestEvent) error {
	path := e.Request.URL.Path
	mutating := e.Request.Method == http.MethodPost || e.Request.Method == http.MethodPatch || e.Request.Method == http.MethodPut || e.Request.Method == http.MethodDelete
	controlled := strings.HasPrefix(path, "/api/infrareveal/sessions") || strings.HasPrefix(path, "/api/infrareveal/lab-gate/") || strings.HasPrefix(path, "/api/infrareveal/routes/") || path == "/api/batch" || (strings.HasPrefix(path, "/api/collections/") && strings.Contains(path, "/records"))
	if !mutating || !controlled {
		return e.Next()
	}
	if err := lockOperation(e.Request.Context(), &g.operations); err != nil {
		return err
	}
	defer g.operations.Unlock()
	if g.closed {
		return e.JSON(http.StatusServiceUnavailable, map[string]string{"error": "Gateway is stopping"})
	}
	const sessions = "/api/infrareveal/sessions"
	current := g.CurrentSessionID()
	changesCapture := e.Request.Method != http.MethodPatch && (path == sessions || (current != "" && (path == sessions+"/"+current || path == sessions+"/"+current+"/end")))
	// Admin CRUD can also change active session identity. Drain all session
	// mutations and outer batches before their record hooks install a new ID.
	// Product PATCH only renames, so it does not interrupt capture.
	if strings.HasPrefix(path, "/api/collections/") {
		parts := strings.Split(strings.TrimPrefix(path, "/api/collections/"), "/")
		if len(parts) >= 2 && parts[1] == "records" {
			collection, err := g.app.FindCachedCollectionByNameOrId("sessions")
			if err != nil {
				return err
			}
			changesCapture = parts[0] == "sessions" || parts[0] == collection.Id
		}
	}
	if changesCapture || path == "/api/batch" {
		resume, err := g.pauseObservation(e.Request.Context())
		if err != nil {
			return e.InternalServerError("Cannot drain observation", err)
		}
		defer resume()
	}
	return e.Next()
}
