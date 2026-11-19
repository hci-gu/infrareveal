package gateway

import (
	"fmt"
	"myapp/observer"
	"myapp/routing"
	"os"
	"strconv"
)

// Config is captured once at process entry. Constructing a runtime has no I/O.
type Config struct {
	Routes                                          routing.Config
	Observation                                     observer.Config
	APInterface, InternetInterface, SSID, GeoIPPath string
	Demo                                            bool
	DemoRetentionMinutes                            int
}

func ConfigFromEnv() (Config, error) {
	ap := envOrDefault("AP_IFACE", "wlan0")
	c := Config{
		Routes:      routing.ConfigFromEnv(),
		Observation: observer.ConfigFromEnv(ap), APInterface: ap, InternetInterface: envOrDefault("INTERNET_IFACE", "eth0"),
		SSID: envOrDefault("SSID", "Infrareveal"), GeoIPPath: envOrDefault("GEOIP_CITY_DB", "./geoip/city.mmdb"),
		Demo:                 os.Getenv("DEMO_MODE") == "true",
		DemoRetentionMinutes: 30,
	}
	var err error
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
