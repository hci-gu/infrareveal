package data

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/pocketbase/dbx"
	"github.com/pocketbase/pocketbase/core"
)

// Checkpoints moves routine WAL syncing off the single capture writer. PASSIVE
// never waits for a reader to release its snapshot. A larger automatic threshold
// remains as a fallback if the worker cannot run; synchronous=NORMAL is unchanged.
// The gateway owns exactly one worker and joins it before closing the database.
type Checkpoints struct {
	cancel   context.CancelFunc
	done     chan struct{}
	mu       sync.Mutex
	app      core.App
	previous int
	restored bool
}

func StartCheckpoints(app core.App) (*Checkpoints, error) {
	db, ok := app.ConcurrentDB().(*dbx.DB)
	if !ok {
		return nil, fmt.Errorf("checkpoint worker requires concurrent storage")
	}
	ctx, cancel := context.WithCancel(context.Background())
	connection, err := db.DB().Conn(ctx)
	if err != nil {
		cancel()
		return nil, err
	}
	// Own this connection so the zero wait policy never leaks into API reads.
	var busyTimeout int
	if err = connection.QueryRowContext(ctx, "PRAGMA busy_timeout").Scan(&busyTimeout); err == nil {
		_, err = connection.ExecContext(ctx, "PRAGMA busy_timeout=0")
	}
	if err != nil {
		cancel()
		_ = connection.Close()
		return nil, err
	}
	release := func() {
		_, _ = connection.ExecContext(context.Background(), fmt.Sprintf("PRAGMA busy_timeout=%d", busyTimeout))
		_ = connection.Close()
	}
	var previous int
	if err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint").Row(&previous); err != nil {
		cancel()
		release()
		return nil, err
	}
	if _, err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint=16384").Execute(); err != nil {
		cancel()
		release()
		return nil, err
	}
	w := &Checkpoints{cancel: cancel, done: make(chan struct{}), app: app, previous: previous}
	go func() {
		defer close(w.done)
		defer release()
		// Avoid repeatedly colliding with one-second capture and browser timers.
		timer := time.NewTimer(time.Second)
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-timer.C:
				if err := checkpoint(ctx, connection); err != nil && ctx.Err() == nil {
					log.Printf("background WAL checkpoint: %v", err)
					// Restore the ordinary writer-side fallback after an unexpected error.
					if err := w.restore(ctx); err != nil {
						log.Printf("restore WAL checkpoint: %v", err)
					}
					return
				}
				timer.Reset(time.Duration(750+rand.IntN(500)) * time.Millisecond)
			}
		}
	}()
	return w, nil
}

func checkpoint(ctx context.Context, connection *sql.Conn) error {
	var busy, pages, written int
	if err := connection.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&busy, &pages, &written); err != nil {
		return err
	}
	// Continuous short readers can prevent WAL reuse even after its frames are
	// copied. Try to reclaim a large, fully checkpointed WAL without waiting for
	// any reader or writer. A busy result is normal and retried on a later tick.
	if busy == 0 && pages >= 16384 && pages == written {
		return connection.QueryRowContext(ctx, "PRAGMA wal_checkpoint(TRUNCATE)").Scan(&busy, &pages, &written)
	}
	return nil
}

func (w *Checkpoints) restore(ctx context.Context) error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.restored {
		return nil
	}
	_, err := w.app.NonconcurrentDB().NewQuery(fmt.Sprintf("PRAGMA wal_autocheckpoint=%d", w.previous)).WithContext(ctx).Execute()
	if err == nil {
		w.restored = true
	}
	return err
}

func (w *Checkpoints) Close(ctx context.Context) error {
	w.cancel()
	select {
	case <-w.done:
		return w.restore(ctx)
	case <-ctx.Done():
		return errors.Join(ctx.Err(), fmt.Errorf("checkpoint worker still running"))
	}
}
