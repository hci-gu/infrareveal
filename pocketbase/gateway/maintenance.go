package gateway

import (
	"context"
	"errors"
	"log"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
	"myapp/labgate"
	"myapp/observer"
	"myapp/routing"
	"myapp/timeline"
)

const ephemeralWindow = 5 * time.Minute // Compatibility default for existing sessions.

func sessionRetention(record *core.Record) time.Duration { return timeline.RetentionWindow(record) }

// Keep the original creation date for identity; started_at is the retained edge.
func normalizeEphemeralSession(record *core.Record, now time.Time) {
	if !record.GetBool("ephemeral") {
		return
	}
	record.Set("active", true)
	record.Set("ended_at", "")
	if record.GetDateTime("started_at").IsZero() {
		record.Set("started_at", now)
	} else if record.GetDateTime("started_at").Time().Before(now.Add(-sessionRetention(record))) {
		record.Set("started_at", now.Add(-sessionRetention(record)))
	}
}

func (g *Runtime) maintain(ctx context.Context) {
	var lastPacketSweep time.Time
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil {
			return
		}
		now := time.Now().UTC()
		g.operations.Lock()
		if ctx.Err() != nil {
			g.operations.Unlock()
			return
		}
		packetDue := now.Sub(lastPacketSweep) >= time.Minute
		err := g.sweep(now, packetDue)
		if packetDue {
			lastPacketSweep = now
		}
		g.operations.Unlock()
		g.updateDemoMaintenance(now, err)
		if err != nil {
			log.Printf("demo maintenance: %v", err)
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Set-based deletion intentionally avoids per-row SSE storms. The browser owns
// age-based eviction, including while disconnected. SQLite reuses freed pages.
// Short transactions serialize against observer writes. No ordinary session rows
// are deleted; shared destination evidence is retained while any flow/route uses it.
func (g *Runtime) pruneEphemeralSessions(now time.Time) error {
	app := g.app
	sessions, err := app.FindRecordsByFilter("sessions", "ephemeral=true", "", 0, 0)
	var errs []error
	if err != nil {
		errs = append(errs, err)
	}
	for _, session := range sessions {
		err = app.RunInTransaction(func(tx core.App) error {
			// A settings edit may have disabled retention since the outer query.
			current, err := tx.FindRecordById("sessions", session.Id)
			if err != nil {
				return err
			}
			if !current.GetBool("ephemeral") {
				return nil
			}
			if err := g.collectDemoDomains(tx, current); err != nil {
				return err
			}
			cutoff := now.Add(-sessionRetention(current))
			if err := observer.RetainSession(tx, session.Id, cutoff); err != nil {
				return err
			}
			if err := routing.RetainSession(tx, session.Id, cutoff); err != nil {
				return err
			}
			if err := labgate.RetainSession(tx, session.Id, cutoff); err != nil {
				return err
			}
			_, err = tx.DB().NewQuery(`UPDATE sessions SET active=true, ended_at='', started_at=CASE WHEN started_at < {:cut} OR started_at='' THEN {:cut} ELSE started_at END WHERE id={:session}`).Bind(dbx.Params{"session": session.Id, "cut": cutoff.UTC().Format("2006-01-02 15:04:05.000Z")}).Execute()
			if err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			errs = append(errs, err)
		}
	}
	errs = append(errs, observer.PruneDomainCatalogueCheckpoints(app))
	if len(sessions) == 0 {
		return errors.Join(append(errs, routing.RetainShared(app, now.Add(-24*time.Hour), now.Add(-24*time.Hour)))...)
	}
	// Shared caches are bounded independently, even when route probing is disabled.
	sharedWindow := ephemeralWindow
	for _, session := range sessions {
		if window := sessionRetention(session); window > sharedWindow {
			sharedWindow = window
		}
	}
	errs = append(errs, observer.RetainShared(app, now.Add(-sharedWindow)), routing.RetainShared(app, now.Add(-sharedWindow), now.Add(-24*time.Hour)))
	return errors.Join(errs...)
}

// Chores share a clock, not a failure domain: a catalogue error must not suspend
// global cache bounds or ordinary inactive-session packet detail expiry.
func (g *Runtime) sweep(now time.Time, packetDue bool) error {
	err := g.pruneEphemeralSessions(now)
	if packetDue {
		_, packetErr := observer.PruneInactiveActivity(g.app, now.Add(-g.config.Observation.Packet.Retention), 500)
		err = errors.Join(err, packetErr)
	}
	return err
}
