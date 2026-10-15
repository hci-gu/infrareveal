package gateway

import (
	"fmt"
	"myapp/debugtrace"
	"myapp/labgate"
	"myapp/observer"
	"myapp/routing"
	"net/netip"
	"os"
	"strconv"
	"time"
)

// Config is captured once at process entry. Constructing a runtime has no I/O.
type Config struct {
	Trace                                                             debugtrace.Config
	Gate                                                              labgate.Config
	Routes                                                            routing.Config
	Observation                                                       observer.Config
	APInterface, InternetInterface, ClientSubnetText, SSID, GeoIPPath string
	ClientSubnet                                                      netip.Prefix
	Demo                                                              bool
	Diagnostics                                                       bool
	DemoRetentionMinutes                                              int
	DiagnosticRetention                                               time.Duration
	DiagnosticMaxBytes                                                int64
}

func ConfigFromEnv() (Config, error) {
	ap := envOrDefault("AP_IFACE", "wlan0")
	c := Config{
		Trace: debugtrace.ConfigFromEnv(), Gate: labgate.ConfigFromEnv(), Routes: routing.ConfigFromEnv(),
		Observation: observer.ConfigFromEnv(ap), APInterface: ap, InternetInterface: envOrDefault("INTERNET_IFACE", "eth0"),
		ClientSubnetText: envOrDefault("LAB_GATE_CLIENT_SUBNET", "10.0.0.0/24"),
		SSID:             envOrDefault("SSID", "Infrareveal"), GeoIPPath: "./geoip/city.mmdb",
		Demo: os.Getenv("DEMO_MODE") == "true", Diagnostics: os.Getenv("DIAGNOSTICS_ENABLED") == "true",
		DemoRetentionMinutes: 30,
	}
	var err error
	c.ClientSubnet, err = netip.ParsePrefix(c.ClientSubnetText)
	if err != nil {
		return c, fmt.Errorf("invalid LAB_GATE_CLIENT_SUBNET: %w", err)
	}
	if c.Demo {
		c.DemoRetentionMinutes, err = strconv.Atoi(envOrDefault("DEMO_RETENTION_MINUTES", "30"))
		if err != nil || c.DemoRetentionMinutes < 1 || c.DemoRetentionMinutes > 1440 {
			return c, fmt.Errorf("DEMO_RETENTION_MINUTES must be an integer from 1 to 1440")
		}
	}
	c.Observation.Diagnostics = c.Diagnostics
	c.Routes.Diagnostics = c.Diagnostics
	minutes, err := strconv.Atoi(envOrDefault("DIAGNOSTICS_RETENTION_MINUTES", "60"))
	if err != nil || minutes < 1 || minutes > 1440 {
		return c, fmt.Errorf("DIAGNOSTICS_RETENTION_MINUTES must be an integer from 1 to 1440")
	}
	megabytes, err := strconv.Atoi(envOrDefault("DIAGNOSTICS_MAX_MB", "16"))
	if err != nil || megabytes < 1 || megabytes > 256 {
		return c, fmt.Errorf("DIAGNOSTICS_MAX_MB must be an integer from 1 to 256")
	}
	c.DiagnosticRetention = time.Duration(minutes) * time.Minute
	c.DiagnosticMaxBytes = int64(megabytes) * 1024 * 1024
	return c, nil
}
func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
