package debugtrace

import (
	"context"
	"testing"
)

func TestConfigFromEnvBoundsInvalidValues(t *testing.T) {
	t.Setenv("DEBUG_TRACE_ENABLED", "true")
	t.Setenv("DEBUG_TRACE_RING_EVENTS", "3")
	t.Setenv("DEBUG_TRACE_MAX_BATCH", "999")
	config := ConfigFromEnv()
	if !config.Enabled || config.RingEvents != 20_000 || config.MaxBatch != 200 {
		t.Fatalf("unexpected bounded config: %#v", config)
	}
}

func TestDisabledRuntimeIsOnlyANopSink(t *testing.T) {
	hub, sink := NewRuntime(context.Background(), Config{Enabled: false})
	if hub != nil || !sink.TryEmit(Event{}) || !sink.TryBurst(BurstInput{}) {
		t.Fatal("disabled runtime should allocate no hub and return an inert sink")
	}
}
