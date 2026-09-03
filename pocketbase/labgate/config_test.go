package labgate

import (
	"bytes"
	"log"
	"strings"
	"testing"
	"time"
)

func TestConfigFromEnvBoundsAndSecretSafeLogging(t *testing.T) {
	t.Setenv("LAB_GATE_ENABLED", "true")
	t.Setenv("LAB_GATE_QUEUE_NUM", "70000")
	t.Setenv("LAB_GATE_MAX_PENDING_FLOWS", "99999")
	t.Setenv("LAB_GATE_FLOW_TIMEOUT_MS", "1")
	t.Setenv("LAB_GATE_CONTROL_TOKEN_FILE", "/run/secrets/lab-token")
	t.Setenv("LAB_GATE_ALLOWED_ORIGINS", " https://debug.example, http://localhost:5174 ")
	config := ConfigFromEnv()
	if !config.Enabled || config.QueueNumber != defaultQueueNumber || config.MaxPendingFlows != 128 || config.FlowTimeout != 10*time.Second {
		t.Fatalf("unsafe values were not clamped to defaults: %+v", config)
	}
	if len(config.AllowedOrigins) != 2 {
		t.Fatalf("origins = %#v", config.AllowedOrigins)
	}

	var output bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&output)
	t.Cleanup(func() { log.SetOutput(previous) })
	config.LogEffective()
	if strings.Contains(output.String(), "/run/secrets/lab-token") {
		t.Fatal("effective config leaked the token file path")
	}
	if !strings.Contains(output.String(), "token_configured=true") {
		t.Fatal("effective config omitted token availability")
	}
}

func TestConfigValidation(t *testing.T) {
	valid := testConfig()
	if err := valid.Validate(); err != nil {
		t.Fatal(err)
	}
	duplicate := valid
	duplicate.DNSQueueNumber = duplicate.QueueNumber
	if err := duplicate.Validate(); err == nil {
		t.Fatal("duplicate queue numbers accepted")
	}
	unsafe := valid
	unsafe.MaxHeldPackets = unsafe.MaxPendingFlows - 1
	if err := unsafe.Validate(); err == nil {
		t.Fatal("unsafe held packet limit accepted")
	}
}
