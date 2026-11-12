package data_test

import (
	"context"
	"testing"
	"time"

	"myapp/data"
	"myapp/testsupport"
)

func TestCheckpointWorkerRestoresWriterAndPreservesCommits(t *testing.T) {
	app := testsupport.App(t)
	var original int
	if err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint").Row(&original); err != nil {
		t.Fatal(err)
	}
	var version string
	if err := app.DB().NewQuery("SELECT sqlite_version()").Row(&version); err != nil {
		t.Fatal(err)
	}
	t.Logf("SQLite %s", version)
	w, err := data.StartCheckpoints(app)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for i := 0; i < 10; i++ {
		if _, err := data.Write(app, "sessions", data.Session{ID: data.NewID(), Name: "checkpoint"}); err != nil {
			t.Fatal(err)
		}
	}
	time.Sleep(1100 * time.Millisecond)
	if err := w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(ctx); err != nil {
		t.Fatal(err)
	}
	var restored, count int
	if err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint").Row(&restored); err != nil {
		t.Fatal(err)
	}
	if err := app.DB().NewQuery("SELECT count(*) FROM sessions WHERE name='checkpoint'").Row(&count); err != nil {
		t.Fatal(err)
	}
	if restored != original || count != 10 {
		t.Fatalf("checkpoint lost data or configuration: %d/%d, %d", restored, original, count)
	}
}
