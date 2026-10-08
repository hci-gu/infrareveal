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
)

// Config is captured once at process entry. Constructing a runtime has no I/O.
type Config struct {
	Trace                                                             debugtrace.Config
	Gate                                                              labgate.Config
	Routes                                                            routing.Config
	Observation                                                       observer.Config
	APInterface, InternetInterface, ClientSubnetText, SSID, GeoIPPath string
	ClientSubnet                                                      netip.Prefix
	Demo, DomainCatalogue                                             bool
	DemoRetentionMinutes                                              int
}

func ConfigFromEnv() (Config, error) {
	ap := envOrDefault("AP_IFACE", "wlan0")
	c := Config{
		Trace: debugtrace.ConfigFromEnv(), Gate: labgate.ConfigFromEnv(), Routes: routing.ConfigFromEnv(),
		Observation: observer.ConfigFromEnv(ap), APInterface: ap, InternetInterface: envOrDefault("INTERNET_IFACE", "eth0"),
		ClientSubnetText: envOrDefault("LAB_GATE_CLIENT_SUBNET", "10.0.0.0/24"),
		SSID:             envOrDefault("SSID", "Infrareveal"), GeoIPPath: "./geoip/city.mmdb",
		Demo: os.Getenv("DEMO_MODE") == "true", DomainCatalogue: envOrDefault("DEMO_DOMAIN_CATALOGUE", "true") == "true",
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
	return c, nil
}
func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
