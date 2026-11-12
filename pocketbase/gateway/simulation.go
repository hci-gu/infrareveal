package gateway

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/pocketbase/pocketbase/core"
	"github.com/pocketbase/pocketbase/tools/router"
	"myapp/observer"
)

const simulationDuration = 3 * time.Minute

type simulationStatus struct {
	Active    bool   `json:"active"`
	SessionID string `json:"session_id,omitempty"`
	ExpiresMS int64  `json:"expires_ms,omitempty"`
	MapPath   string `json:"map_path,omitempty"`
	Lanes     int    `json:"lanes,omitempty"`
}

type simulationRun struct {
	status      simulationStatus
	observation *observer.Runtime
	cancel      context.CancelFunc
	stopping    bool
}

func (g *Runtime) registerSimulationRoutes(r *router.Router[*core.RequestEvent]) {
	// The operation lock serializes duplicate starts, clear and shutdown.
	for _, method := range []string{http.MethodGet, http.MethodPost, http.MethodDelete} {
		r.Route(method, "/api/infrareveal/simulation", func(e *core.RequestEvent) error {
			if err := lockOperation(e.Request.Context(), &g.operations); err != nil {
				return err
			}
			defer g.operations.Unlock()
			if g.closed {
				return e.JSON(http.StatusServiceUnavailable, map[string]string{"message": "Gateway is stopping"})
			}
			switch e.Request.Method {
			case http.MethodPost:
				status, created, err := g.startSimulation(simulationDuration)
				if err != nil {
					return e.InternalServerError("Cannot start simulation", err)
				}
				code := http.StatusOK
				if created {
					code = http.StatusCreated
				}
				return e.JSON(code, status)
			case http.MethodDelete:
				if id := e.Request.URL.Query().Get("session_id"); id != "" && g.simulation != nil && id != g.simulation.status.SessionID {
					return e.JSON(http.StatusConflict, map[string]string{"message": "A different simulation is running"})
				}
				if err := g.stopSimulation(e.Request.Context()); err != nil {
					return e.InternalServerError("Cannot clean up simulation", err)
				}
				return e.NoContent(http.StatusNoContent)
			default:
				if g.simulation != nil {
					return e.JSON(http.StatusOK, g.simulation.status)
				}
				return e.JSON(http.StatusOK, simulationStatus{})
			}
		})
	}
}

// Caller holds operations. Repeated POSTs join the same bounded run without
// extending its deadline, making retries and multiple dashboard clients safe.
func (g *Runtime) startSimulation(duration time.Duration) (simulationStatus, bool, error) {
	if g.simulation != nil {
		return g.simulation.status, false, nil
	}
	if err := g.cleanupSimulations(); err != nil {
		return simulationStatus{}, false, err
	}
	collection, err := g.app.FindCollectionByNameOrId("sessions")
	if err != nil {
		return simulationStatus{}, false, err
	}
	expires := time.Now().Add(duration)
	record := core.NewRecord(collection)
	record.Set("name", "Simulated demo · auto-deletes after 3 minutes")
	record.Set("active", true)
	record.Set("simulation_expires_ms", expires.UnixMilli())
	record.Set("retention_minutes", 5)
	if err = g.app.Save(record); err != nil {
		return simulationStatus{}, false, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &simulationRun{status: simulationStatus{Active: true, SessionID: record.Id, ExpiresMS: expires.UnixMilli(), MapPath: "/map/" + record.Id, Lanes: observer.SimulationLanes}, cancel: cancel,
		observation: observer.NewSimulation(g.app, record.Id, expires, g.config.Diagnostics)}
	g.simulation = run
	run.observation.Start()
	go g.watchSimulation(ctx, run)
	return run.status, true, nil
}

func (g *Runtime) watchSimulation(ctx context.Context, run *simulationRun) {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		if err := lockOperation(ctx, &g.operations); err != nil {
			return
		}
		if g.simulation != run {
			g.operations.Unlock()
			return
		}
		record, err := g.app.FindRecordById("sessions", run.status.SessionID)
		expired := time.Now().UnixMilli() >= run.status.ExpiresMS
		if run.stopping || expired || errors.Is(err, sql.ErrNoRows) || (err == nil && !record.GetBool("active")) {
			cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			err = g.stopSimulation(cleanup)
			cancel()
		}
		g.operations.Unlock()
		if err != nil {
			log.Printf("simulation cleanup: %v", err)
		}
	}
}

// Drain every writer before deleting. Failure retains ownership for a retry;
// the source has its own deadline, so failed cleanup never prolongs generation.
func (g *Runtime) stopSimulation(ctx context.Context) error {
	if g.simulation == nil {
		// Commands such as --version terminate without opening storage.
		if !g.app.IsBootstrapped() {
			return nil
		}
		return g.cleanupSimulations()
	}
	run := g.simulation
	run.stopping = true
	if err := run.observation.Close(ctx); err != nil {
		return err
	}
	if err := g.cleanupSimulations(); err != nil {
		return err
	}
	run.cancel()
	g.simulation = nil
	return nil
}

// Durable markers also recover demos interrupted by a process crash. Session
// deletion hooks remove chunks, coverage, blocks and diagnostics, then prune
// unreferenced destination snapshots. Real recordings and probe charges stay.
func (g *Runtime) cleanupSimulations() error {
	sessions, err := g.app.FindRecordsByFilter("sessions", "simulation_expires_ms > 0", "", 0, 0)
	if err != nil {
		return err
	}
	for _, session := range sessions {
		if err := g.app.Delete(session); err != nil {
			return fmt.Errorf("delete simulation %s: %w", session.Id, err)
		}
	}
	return nil
}
