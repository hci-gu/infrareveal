package data

import (
	"context"
	"errors"
	"fmt"
	"log"
	"sync"
	"time"

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
	var previous int
	if err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint").Row(&previous); err != nil {
		return nil, err
	}
	if _, err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint=16384").Execute(); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	w := &Checkpoints{cancel: cancel, done: make(chan struct{}), app: app, previous: previous}
	go func() {
		defer close(w.done)
		ticker := time.NewTicker(time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if _, err := app.ConcurrentDB().NewQuery("PRAGMA wal_checkpoint(PASSIVE)").WithContext(ctx).Execute(); err != nil && ctx.Err() == nil {
					log.Printf("background WAL checkpoint: %v", err)
					// Restore the ordinary writer-side fallback after an unexpected error.
					if err := w.restore(ctx); err != nil {
						log.Printf("restore WAL checkpoint: %v", err)
					}
					return
				}
			}
		}
	}()
	return w, nil
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
