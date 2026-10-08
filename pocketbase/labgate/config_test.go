package labgate

import (
	"bytes"
	"context"
	"log"
	"reflect"
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

func TestCapturedConfigAndConstructorDefaultsIgnoreLaterEnvironmentChanges(t *testing.T) {
	for name, value := range map[string]string{
		"LAB_GATE_ENABLED": "false", "LAB_GATE_FAIL_OPEN": "true",
		"LAB_GATE_QUEUE_NUM": "42", "LAB_GATE_STRICT_QUEUE_NUM": "43", "LAB_GATE_DNS_QUEUE_NUM": "44",
		"LAB_GATE_MAX_PENDING_FLOWS": "128", "LAB_GATE_MAX_HELD_PACKETS": "768",
		"LAB_GATE_FLOW_TIMEOUT_MS": "10000", "LAB_GATE_ESTABLISHED_TIMEOUT_MS": "500",
		"LAB_GATE_DNS_TIMEOUT_MS": "2000", "LAB_GATE_DECISION_CACHE_SECONDS": "120",
		"LAB_GATE_CONTROL_TOKEN_FILE": "", "LAB_GATE_ALLOWED_ORIGINS": "",
	} {
		t.Setenv(name, value)
	}
	captured := ConfigFromEnv()
	for name, value := range map[string]string{
		"LAB_GATE_ENABLED": "true", "LAB_GATE_FAIL_OPEN": "false",
		"LAB_GATE_QUEUE_NUM": "71", "LAB_GATE_STRICT_QUEUE_NUM": "71", "LAB_GATE_DNS_QUEUE_NUM": "71",
		"LAB_GATE_MAX_PENDING_FLOWS": "1024", "LAB_GATE_MAX_HELD_PACKETS": "8",
		"LAB_GATE_FLOW_TIMEOUT_MS": "100", "LAB_GATE_ESTABLISHED_TIMEOUT_MS": "100",
		"LAB_GATE_DNS_TIMEOUT_MS": "100", "LAB_GATE_DECISION_CACHE_SECONDS": "1",
		"LAB_GATE_CONTROL_TOKEN_FILE": "/changed/token", "LAB_GATE_ALLOWED_ORIGINS": "https://changed.example",
	} {
		t.Setenv(name, value)
	}
	defaults := defaultConfig()
	defaults.FailOpen = false // An explicit zero-value boolean is still preserved.
	for _, test := range []struct {
		name           string
		config, expect Config
	}{
		{"captured", captured, captured},
		{"zero values", Config{}, defaults},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := ValidateConfig(test.config); err != nil {
				t.Fatalf("validation used changed environment: %v", err)
			}
			controller, err := NewController(context.Background(), test.config, nil, nil, nil, nil)
			if err != nil {
				t.Fatal(err)
			}
			defer func() {
				if err := controller.Close(testContext(t)); err != nil {
					t.Error(err)
				}
			}()
			if !reflect.DeepEqual(controller.config, test.expect) {
				t.Fatalf("constructor changed configuration:\ngot  %+v\nwant %+v", controller.config, test.expect)
			}
		})
	}
}
