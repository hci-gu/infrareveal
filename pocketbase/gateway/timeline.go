package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/data"
	"myapp/timeline"
)

func registerSessionTimelineRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	RegisterSessionTimelineRoutes(r, app)
}

// RegisterSessionTimelineRoutes also serves isolated load-test databases.
func RegisterSessionTimelineRoutes(r *router.Router[*core.RequestEvent], app core.App) {
	reader := timeline.New(app)
	app.OnTerminate().BindFunc(func(e *core.TerminateEvent) error { reader.Close(); return e.Next() })
	r.GET("/api/infrareveal/sessions", func(e *core.RequestEvent) error {
		rows, err := app.FindRecordsByFilter("sessions", "", "-started_ms", 200, 0)
		if err != nil {
			return e.InternalServerError("Cannot load sessions", err)
		}
		items := make([]data.Session, 0, len(rows))
		for _, row := range rows {
			session, err := data.Decode[data.Session](row)
			if err != nil {
				return err
			}
			items = append(items, session)
		}
		return e.JSON(http.StatusOK, map[string]any{"items": items})
	})
	r.GET("/api/infrareveal/sessions/{id}/manifest", func(e *core.RequestEvent) error {
		manifest, err := reader.Manifest(e.Request.PathValue("id"), time.Now())
		if err != nil {
			return timelineError(e, err)
		}
		// Stamp after the read: storage contention is part of capture age, not
		// a reason to give the display a clock from before the request waited.
		manifest.ServerMS = time.Now().UnixMilli()
		return e.JSON(http.StatusOK, manifest)
	})
	r.GET("/api/infrareveal/sessions/{id}/map", func(e *core.RequestEvent) error {
		query, err := timeline.ParseQuery(e.Request.URL.Query())
		if err != nil {
			return e.BadRequestError(err.Error(), nil)
		}
		window, err := reader.Window(e.Request.PathValue("id"), query)
		if err != nil {
			return timelineError(e, err)
		}
		return e.JSON(http.StatusOK, window)
	})
	r.GET("/api/infrareveal/sessions/{id}/blocks", func(e *core.RequestEvent) error {
		query, err := timeline.ParseBlockQuery(e.Request.URL.Query())
		if err != nil {
			return e.BadRequestError(err.Error(), nil)
		}
		page, err := reader.Blocks(e.Request.PathValue("id"), query)
		if err != nil {
			return timelineError(e, err)
		}
		return e.JSON(http.StatusOK, page)
	})
	r.GET("/api/infrareveal/sessions/{id}/blocks/{block}", func(e *core.RequestEvent) error {
		block, err := reader.Block(e.Request.PathValue("id"), e.Request.PathValue("block"))
		if err != nil {
			return timelineError(e, err)
		}
		return e.JSON(http.StatusOK, block)
	})
	r.GET("/api/infrareveal/sessions/{id}/revisions", func(e *core.RequestEvent) error { return streamSessionRevisions(e, app) })
}

func timelineError(e *core.RequestEvent, err error) error {
	switch {
	case errors.Is(err, timeline.ErrSessionNotFound), errors.Is(err, sql.ErrNoRows):
		return e.NotFoundError("Session or block not found", nil)
	case errors.Is(err, timeline.ErrRevisionChanged), errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded), errors.Is(err, sql.ErrTxDone):
		return e.JSON(http.StatusConflict, map[string]string{"error": err.Error()})
	case errors.Is(err, timeline.ErrWindowTooLarge):
		return e.JSON(http.StatusRequestEntityTooLarge, map[string]string{"error": err.Error()})
	case errors.Is(err, timeline.ErrInvalidQuery):
		return e.BadRequestError(err.Error(), nil)
	default:
		return e.InternalServerError("Cannot load session data", err)
	}
}

// One lightweight revision stream replaces subscriptions to every collector
// collection. Polling only the session row also observes transactional SQL bumps.
func streamSessionRevisions(e *core.RequestEvent, app core.App) error {
	id := e.Request.PathValue("id")
	manifest, err := timeline.New(app).Manifest(id, time.Now())
	if err != nil {
		return timelineError(e, err)
	}
	controller := http.NewResponseController(e.Response)
	e.Response.Header().Set("Content-Type", "text/event-stream")
	e.Response.Header().Set("Cache-Control", "no-store")
	e.Response.Header().Set("X-Accel-Buffering", "no")
	e.Response.WriteHeader(http.StatusOK)
	send := func(kind string, manifest data.Manifest) error {
		// Ticker values can also be stale after a delayed read or send.
		payload, err := json.Marshal(map[string]any{"revision": manifest.Revision, "retained_from_ms": manifest.RetainedFromMS, "server_ms": time.Now().UnixMilli()})
		if err != nil {
			return err
		}
		_ = controller.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err = fmt.Fprintf(e.Response, "id: %s\nevent: %s\ndata: %s\n\n", strconv.FormatInt(manifest.Revision, 10), kind, payload); err != nil {
			return err
		}
		return e.Flush()
	}
	if err = send("revision", manifest); err != nil {
		return nil
	}
	revision := manifest.Revision
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	lastSent := time.Now()
	for {
		select {
		case <-e.Request.Context().Done():
			return nil
		case now := <-ticker.C:
			manifest, err = timeline.New(app).Manifest(id, now)
			if err != nil {
				return nil
			}
			if manifest.Revision != revision {
				if send("revision", manifest) != nil {
					return nil
				}
				revision = manifest.Revision
				lastSent = now
			} else if now.Sub(lastSent) >= 15*time.Second {
				if send("heartbeat", manifest) != nil {
					return nil
				}
				lastSent = now
			}
		}
	}
}
