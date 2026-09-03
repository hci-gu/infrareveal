package debugtrace

import (
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Enabled          bool
	RingEvents       int
	Retention        time.Duration
	IngressBuffer    int
	SubscriberBuffer int
	BatchInterval    time.Duration
	MaxBatch         int
	MaxSubscribers   int
}

func ConfigFromEnv() Config {
	return Config{
		Enabled:          boolEnv("DEBUG_TRACE_ENABLED", false),
		RingEvents:       intEnv("DEBUG_TRACE_RING_EVENTS", 20_000, 100, 200_000),
		Retention:        time.Duration(intEnv("DEBUG_TRACE_RETENTION_SECONDS", 30, 5, 300)) * time.Second,
		IngressBuffer:    intEnv("DEBUG_TRACE_INGRESS_BUFFER", 8_192, 128, 131_072),
		SubscriberBuffer: intEnv("DEBUG_TRACE_SUBSCRIBER_BUFFER", 256, 8, 4_096),
		BatchInterval:    time.Duration(intEnv("DEBUG_TRACE_BATCH_MS", 50, 10, 1_000)) * time.Millisecond,
		MaxBatch:         intEnv("DEBUG_TRACE_MAX_BATCH", 200, 1, 200),
		MaxSubscribers:   intEnv("DEBUG_TRACE_MAX_SUBSCRIBERS", 32, 1, 256),
	}
}

func (config Config) LogEffective() {
	log.Printf(
		"debug trace enabled=%t ring_events=%d retention=%s ingress=%d subscriber=%d batch=%s max_batch=%d max_subscribers=%d",
		config.Enabled, config.RingEvents, config.Retention, config.IngressBuffer,
		config.SubscriberBuffer, config.BatchInterval, config.MaxBatch, config.MaxSubscribers,
	)
}

func (config Config) withDefaults() Config {
	defaults := ConfigFromEnv()
	defaults.Enabled = config.Enabled
	if config.RingEvents > 0 {
		defaults.RingEvents = config.RingEvents
	}
	if config.Retention > 0 {
		defaults.Retention = config.Retention
	}
	if config.IngressBuffer > 0 {
		defaults.IngressBuffer = config.IngressBuffer
	}
	if config.SubscriberBuffer > 0 {
		defaults.SubscriberBuffer = config.SubscriberBuffer
	}
	if config.BatchInterval > 0 {
		defaults.BatchInterval = config.BatchInterval
	}
	if config.MaxBatch > 0 {
		defaults.MaxBatch = min(config.MaxBatch, 200)
	}
	if config.MaxSubscribers > 0 {
		defaults.MaxSubscribers = config.MaxSubscribers
	}
	return defaults
}

func boolEnv(name string, fallback bool) bool {
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

func intEnv(name string, fallback, minimum, maximum int) int {
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
