package gateway

import (
	"context"
	"github.com/pocketbase/pocketbase"
	"testing"
)

func TestCloseBeforeBootstrapDoesNotAccessStorage(t *testing.T) {
	app := pocketbase.NewWithConfig(pocketbase.Config{DefaultDataDir: t.TempDir(), HideStartBanner: true})
	g := New(app, Config{})
	if err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if app.IsBootstrapped() || !g.resourcesClosed {
		t.Fatal("closing an unstarted command opened storage or retained resources")
	}
	if err := g.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := g.Start(); err == nil {
		t.Fatal("closed gateway restarted")
	}
}
