package gateway

import (
	"errors"
	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/timeline"
	"net/http"
	"time"
)

func registerSessionTimelineRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	r.GET("/api/infrareveal/sessions/{id}/manifest", func(e *core.RequestEvent) error {
		manifest, err := timeline.New(app).Manifest(e.Request.PathValue("id"), time.Now().UTC())
		if err != nil {
			return e.JSON(http.StatusNotFound, map[string]string{"error": err.Error()})
		}
		return e.JSON(http.StatusOK, manifest)
	})

	r.GET("/api/infrareveal/sessions/{id}/window", func(e *core.RequestEvent) error {
		window, status, err := readTimelineWindow(app, e.Request.PathValue("id"), e.Request.URL.Query())
		if err != nil {
			return e.JSON(status, map[string]string{"error": err.Error()})
		}
		return e.JSON(http.StatusOK, window)
	})
}

func readTimelineWindow(app core.App, id string, values map[string][]string) (timeline.Window, int, error) {
	// Preserve the existing missing-session response before validating the query.
	if _, err := app.FindRecordById("sessions", id); err != nil {
		return timeline.Window{}, http.StatusNotFound, timeline.ErrSessionNotFound
	}
	query, err := timeline.ParseQuery(values)
	if err != nil {
		return timeline.Window{}, http.StatusBadRequest, err
	}
	window, err := timeline.New(app).Window(id, query)
	status := http.StatusOK
	if err != nil {
		status = http.StatusInternalServerError
	}
	if errors.Is(err, timeline.ErrSessionNotFound) {
		status = http.StatusNotFound
	}
	return window, status, err
}
