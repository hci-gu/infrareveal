package debugtrace

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
)

const heartbeatInterval = 15 * time.Second

func RegisterRoutes(r *router.Router[*core.RequestEvent], app core.App, hub *Hub) {
	if hub == nil {
		return
	}
	r.GET("/api/infrareveal/debug/sessions/{id}/trace", func(event *core.RequestEvent) error {
		sessionID := event.Request.PathValue("id")
		if _, err := app.FindRecordById("sessions", sessionID); err != nil {
			return event.JSON(http.StatusNotFound, map[string]string{"error": "session not found"})
		}
		after := uint64(0)
		if value := event.Request.URL.Query().Get("after"); value != "" {
			parsed, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return event.JSON(http.StatusBadRequest, map[string]string{"error": "after must be an unsigned sequence"})
			}
			after = parsed
		}

		subscription, err := hub.Subscribe(event.Request.Context(), sessionID, after)
		if errors.Is(err, ErrMaxSubscribers) {
			return event.JSON(http.StatusServiceUnavailable, map[string]string{"error": err.Error()})
		}
		if err != nil {
			return event.JSON(http.StatusServiceUnavailable, map[string]string{"error": "trace stream unavailable"})
		}
		defer subscription.Close()

		controller := http.NewResponseController(event.Response)
		_ = controller.SetWriteDeadline(time.Time{})
		event.Response.Header().Set("Content-Type", "text/event-stream")
		event.Response.Header().Set("Cache-Control", "no-store")
		event.Response.Header().Set("Connection", "keep-alive")
		event.Response.Header().Set("X-Accel-Buffering", "no")
		event.Response.WriteHeader(http.StatusOK)
		for _, message := range subscription.Initial {
			if err := writeSSE(event.Response, message); err != nil {
				return nil
			}
		}
		if err := event.Flush(); err != nil {
			return nil
		}

		heartbeat := time.NewTicker(heartbeatInterval)
		defer heartbeat.Stop()
		for {
			select {
			case <-event.Request.Context().Done():
				return nil
			case message, ok := <-subscription.Events:
				if !ok {
					return nil
				}
				if err := writeSSE(event.Response, message); err != nil {
					return nil
				}
				if err := event.Flush(); err != nil {
					return nil
				}
			case <-heartbeat.C:
				stats, err := hub.Stats(event.Request.Context())
				if err != nil {
					return nil
				}
				message := StreamMessage{
					Type: "heartbeat", Version: ProtocolVersion, SessionID: sessionID,
					ServerNowMs: time.Now().UnixMilli(), OldestSequence: stats.OldestSequence,
					NewestSequence: stats.NewestSequence, IngressRejected: stats.IngressRejected,
					BurstDiscarded: stats.BurstDiscarded,
				}
				if err := writeSSE(event.Response, message); err != nil {
					return nil
				}
				if err := event.Flush(); err != nil {
					return nil
				}
			}
		}
	})
}

func writeSSE(writer http.ResponseWriter, message StreamMessage) error {
	payload, err := json.Marshal(message)
	if err != nil {
		return err
	}
	if _, err := fmt.Fprintf(writer, "event: %s\ndata: %s\n\n", message.Type, payload); err != nil {
		return err
	}
	return nil
}
