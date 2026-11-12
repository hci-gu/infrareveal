package data_test

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/pocketbase/dbx"

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
	var automatic int
	if err := app.NonconcurrentDB().NewQuery("PRAGMA wal_autocheckpoint").Row(&automatic); err != nil || automatic != 0 {
		t.Fatalf("capture writer still owns automatic checkpoint work: %d, %v", automatic, err)
	}
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

func TestCheckpointReusesLargeWALAfterPinnedReaderFinishes(t *testing.T) {
	app := testsupport.App(t)
	_, err := app.DB().NewQuery("CREATE TABLE checkpoint_fixture (value BLOB)").Execute()
	if err != nil {
		t.Fatal(err)
	}
	w, err := data.StartCheckpoints(app)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = w.Close(context.Background()) })
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	reader, err := app.ConcurrentDB().(*dbx.DB).BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Rollback()
	var count int
	if err := reader.NewQuery("SELECT count(*) FROM checkpoint_fixture").Row(&count); err != nil {
		t.Fatal(err)
	}
	_, err = app.DB().NewQuery("WITH RECURSIVE n(v) AS (SELECT 1 UNION ALL SELECT v+1 FROM n WHERE v<40) INSERT INTO checkpoint_fixture SELECT zeroblob(2097152) FROM n").Execute()
	if err != nil {
		t.Fatal(err)
	}
	wal := filepath.Join(app.DataDir(), "data.db-wal")
	info, err := os.Stat(wal)
	if err != nil || info.Size() < 64*1024*1024 {
		t.Fatalf("expected pinned large WAL: %v, %v", info, err)
	}
	if err := reader.Rollback(); err != nil {
		t.Fatal(err)
	}
	allocated := info.Size()
	deadline := time.Now().Add(8 * time.Second)
	for {
		var busy, pages, written int
		err = app.ConcurrentDB().NewQuery("PRAGMA wal_checkpoint(NOOP)").Row(&busy, &pages, &written)
		if err == nil && pages > 0 && pages == written {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("worker did not checkpoint the WAL: %d/%d, %v", written, pages, err)
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err := app.DB().NewQuery("SELECT count(*) FROM checkpoint_fixture").Row(&count); err != nil || count != 40 {
		t.Fatalf("checkpoint changed committed rows: %d, %v", count, err)
	}
	if _, err := app.DB().NewQuery("INSERT INTO checkpoint_fixture VALUES (zeroblob(4096))").Execute(); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(wal)
	if err != nil || info.Size() != allocated {
		t.Fatalf("checkpoint did not reuse the existing WAL allocation: %v, %v", info, err)
	}
}
