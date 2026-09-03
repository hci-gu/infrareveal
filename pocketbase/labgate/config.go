// Package labgate contains the platform-independent policy engine for the
// opt-in traffic gate. Kernel adapters and HTTP/PocketBase integration sit at
// its edges so the safety policy is testable without Linux or root.
package labgate

import (
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	defaultQueueNumber       = 42
	defaultStrictQueueNumber = 43
	defaultDNSQueueNumber    = 44
)

var ErrInvalidConfig = errors.New("invalid lab gate configuration")

type Config struct {
	Enabled            bool
	QueueNumber        uint16
	StrictQueueNumber  uint16
	DNSQueueNumber     uint16
	MaxPendingFlows    int
	MaxHeldPackets     int
	FlowTimeout        time.Duration
	EstablishedTimeout time.Duration
	DNSTimeout         time.Duration
	DecisionCache      time.Duration
	FailOpen           bool
	ControlTokenFile   string
	AllowedOrigins     []string
	KernelSettings     map[string]string
}

func ConfigFromEnv() Config {
	return Config{
		Enabled:            gateBoolEnv("LAB_GATE_ENABLED", false),
		QueueNumber:        uint16(gateIntEnv("LAB_GATE_QUEUE_NUM", defaultQueueNumber, 1, 65535)),
		StrictQueueNumber:  uint16(gateIntEnv("LAB_GATE_STRICT_QUEUE_NUM", defaultStrictQueueNumber, 1, 65535)),
		DNSQueueNumber:     uint16(gateIntEnv("LAB_GATE_DNS_QUEUE_NUM", defaultDNSQueueNumber, 1, 65535)),
		MaxPendingFlows:    gateIntEnv("LAB_GATE_MAX_PENDING_FLOWS", 128, 1, 1024),
		MaxHeldPackets:     gateIntEnv("LAB_GATE_MAX_HELD_PACKETS", 768, 8, 8192),
		FlowTimeout:        time.Duration(gateIntEnv("LAB_GATE_FLOW_TIMEOUT_MS", 10_000, 100, 60_000)) * time.Millisecond,
		EstablishedTimeout: time.Duration(gateIntEnv("LAB_GATE_ESTABLISHED_TIMEOUT_MS", 500, 100, 10_000)) * time.Millisecond,
		DNSTimeout:         time.Duration(gateIntEnv("LAB_GATE_DNS_TIMEOUT_MS", 2_000, 100, 15_000)) * time.Millisecond,
		DecisionCache:      time.Duration(gateIntEnv("LAB_GATE_DECISION_CACHE_SECONDS", 120, 1, 900)) * time.Second,
		FailOpen:           gateBoolEnv("LAB_GATE_FAIL_OPEN", true),
		ControlTokenFile:   strings.TrimSpace(os.Getenv("LAB_GATE_CONTROL_TOKEN_FILE")),
		AllowedOrigins:     splitCSV(os.Getenv("LAB_GATE_ALLOWED_ORIGINS")),
		KernelSettings:     ReadKernelSettings(),
	}
}

func (config Config) Validate() error {
	if config.QueueNumber == 0 || config.StrictQueueNumber == 0 || config.DNSQueueNumber == 0 {
		return errors.Join(ErrInvalidConfig, errors.New("queue numbers must be between 1 and 65535"))
	}
	if config.QueueNumber == config.StrictQueueNumber || config.QueueNumber == config.DNSQueueNumber || config.StrictQueueNumber == config.DNSQueueNumber {
		return errors.Join(ErrInvalidConfig, errors.New("queue numbers must be distinct"))
	}
	if config.MaxPendingFlows < 1 || config.MaxPendingFlows > 1024 || config.MaxHeldPackets < 8 || config.MaxHeldPackets > 8192 {
		return errors.Join(ErrInvalidConfig, errors.New("queue limits are outside safe bounds"))
	}
	if config.MaxHeldPackets < config.MaxPendingFlows {
		return errors.Join(ErrInvalidConfig, errors.New("held packet limit must not be below pending flow limit"))
	}
	if config.FlowTimeout < 100*time.Millisecond || config.FlowTimeout > 60*time.Second ||
		config.EstablishedTimeout < 100*time.Millisecond || config.EstablishedTimeout > 10*time.Second ||
		config.DNSTimeout < 100*time.Millisecond || config.DNSTimeout > 15*time.Second ||
		config.DecisionCache < time.Second || config.DecisionCache > 15*time.Minute {
		return errors.Join(ErrInvalidConfig, errors.New("timeouts are outside safe bounds"))
	}
	return nil
}

func (config Config) withDefaults() Config {
	defaults := ConfigFromEnv()
	defaults.Enabled = config.Enabled
	defaults.FailOpen = config.FailOpen
	if config.QueueNumber != 0 {
		defaults.QueueNumber = config.QueueNumber
	}
	if config.StrictQueueNumber != 0 {
		defaults.StrictQueueNumber = config.StrictQueueNumber
	}
	if config.DNSQueueNumber != 0 {
		defaults.DNSQueueNumber = config.DNSQueueNumber
	}
	if config.MaxPendingFlows != 0 {
		defaults.MaxPendingFlows = config.MaxPendingFlows
	}
	if config.MaxHeldPackets != 0 {
		defaults.MaxHeldPackets = config.MaxHeldPackets
	}
	if config.FlowTimeout != 0 {
		defaults.FlowTimeout = config.FlowTimeout
	}
	if config.EstablishedTimeout != 0 {
		defaults.EstablishedTimeout = config.EstablishedTimeout
	}
	if config.DNSTimeout != 0 {
		defaults.DNSTimeout = config.DNSTimeout
	}
	if config.DecisionCache != 0 {
		defaults.DecisionCache = config.DecisionCache
	}
	if config.ControlTokenFile != "" {
		defaults.ControlTokenFile = config.ControlTokenFile
	}
	if config.AllowedOrigins != nil {
		defaults.AllowedOrigins = append([]string(nil), config.AllowedOrigins...)
	}
	if config.KernelSettings != nil {
		defaults.KernelSettings = make(map[string]string, len(config.KernelSettings))
		for key, value := range config.KernelSettings {
			defaults.KernelSettings[key] = value
		}
	}
	return defaults
}

// ReadKernelSettings reports the safety-relevant effective target settings.
// It is deliberately read-only: global kernel tuning remains an operator task.
func ReadKernelSettings() map[string]string {
	paths := map[string]string{
		"conntrackCount": "/proc/sys/net/netfilter/nf_conntrack_count",
		"conntrackMax":   "/proc/sys/net/netfilter/nf_conntrack_max",
		"netdevBacklog":  "/proc/sys/net/core/netdev_max_backlog",
		"socketRmemMax":  "/proc/sys/net/core/rmem_max",
	}
	settings := make(map[string]string)
	for name, path := range paths {
		if contents, err := os.ReadFile(path); err == nil {
			settings[name] = strings.TrimSpace(string(contents))
		}
	}
	return settings
}

func (config Config) LogEffective() {
	log.Printf("lab gate enabled=%t fail_open=%t queues=%d/%d/%d max_pending=%d max_held=%d flow_timeout=%s established_timeout=%s dns_timeout=%s cache=%s token_configured=%t allowed_origins=%d",
		config.Enabled, config.FailOpen, config.QueueNumber, config.StrictQueueNumber, config.DNSQueueNumber,
		config.MaxPendingFlows, config.MaxHeldPackets, config.FlowTimeout, config.EstablishedTimeout,
		config.DNSTimeout, config.DecisionCache, config.ControlTokenFile != "", len(config.AllowedOrigins))
}

func gateBoolEnv(name string, fallback bool) bool {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.ParseBool(value)
	if err != nil {
		return fallback
	}
	return parsed
}

func gateIntEnv(name string, fallback, minimum, maximum int) int {
	value := strings.TrimSpace(os.Getenv(name))
	if value == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(value)
	if err != nil || parsed < minimum || parsed > maximum {
		return fallback
	}
	return parsed
}

func splitCSV(value string) []string {
	if strings.TrimSpace(value) == "" {
		return nil
	}
	values := make([]string, 0)
	for _, item := range strings.Split(value, ",") {
		if trimmed := strings.TrimSpace(item); trimmed != "" {
			values = append(values, trimmed)
		}
	}
	return values
}
