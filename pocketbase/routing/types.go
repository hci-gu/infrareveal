// Package routing owns route demand, bounded probing, durable admissions and
// immutable session evidence. It never intercepts client traffic.
package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"myapp/data"
	"os"
	"strconv"
	"time"
)

// Traffic is captured wire-byte demand. Bytes is a delta, never a cumulative
// conntrack counter; no durable connection record is needed.
type Traffic struct {
	Session, NetworkEpoch, IP, Protocol string
	Port                                int
	Bytes                               int64
	At                                  time.Time
}

type Hop = data.Hop
type HopReply = data.HopReply
type Location = data.RouteLocation
type InterfaceEvidence = data.InterfaceEvidence

type target struct {
	IP, Protocol string
	Port         int
}

// A binding keeps the source context and the observed endpoint together across
// admission, a running probe, publication retries, and replay.
type routeBinding struct {
	Session string
	Network string
	Epoch   string
	Target  target
}

func (b routeBinding) key() string { return b.Epoch + "|" + b.Target.key(b.Network) }

func (t target) binding() string           { return fmt.Sprintf("%s|%s|%d", t.IP, t.Protocol, t.Port) }
func (t target) key(network string) string { return hash(network + "|" + t.binding()) }
func hash(s string) string                 { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }

type snapshot struct {
	StopReason    string    `json:"stop_reason,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EngineVersion string    `json:"engine_version,omitempty"`
	Engine        string    `json:"engine,omitempty"`
	ProbeCount    int       `json:"probe_count,omitempty"`
	ProbedTTL     int       `json:"probed_ttl,omitempty"`
	Attempt       string    `json:"attempt"`
	Revision      int       `json:"revision"`
	Method        string    `json:"method"`
	Started       time.Time `json:"started"`
	Measured      time.Time `json:"measured"`
	Finished      time.Time `json:"finished"`
	Hops          []Hop     `json:"hops"`
	Reached       bool      `json:"reached"`
	Error         string    `json:"error"`
	Status        string    `json:"status"`
	Location      *Location `json:"location,omitempty"`
}

func (s snapshot) replies() int {
	n := 0
	for _, h := range s.Hops {
		if h.Address != "" {
			n++
		}
	}
	return n
}

type Config struct {
	MaxPending                                                                      int
	Interval, ProbeDeadline, FreshTTL, StaleTTL                                     time.Duration
	Engine                                                                          string
	ASNDBPath                                                                       string
	MaxTargets, MaxAttempts, HourlyAttempts, ManualAttempts, MaxSnapshots, MaxBytes int
	MinBytes                                                                        int64
	Cooldown                                                                        time.Duration
	Diagnostics                                                                     bool
}

func defaultConfig() Config {
	return Config{MaxPending: 256, Interval: 250 * time.Millisecond,
		ProbeDeadline: 45 * time.Second, FreshTTL: 10 * time.Minute, StaleTTL: time.Hour,
		Engine: "scamper", ASNDBPath: "./geoip/asn.mmdb", MaxTargets: 20, MaxAttempts: 40,
		HourlyAttempts: 40, ManualAttempts: 10,
		MaxSnapshots: 100, MaxBytes: 16 * 1024 * 1024,
		MinBytes: 1024 * 1024, Cooldown: 30 * time.Minute}
}

func ConfigFromEnv() Config {
	c := defaultConfig()
	if engine := os.Getenv("ROUTE_ENGINE"); engine == "off" {
		c.Engine = engine
	}
	if path := os.Getenv("ROUTE_ASN_DB"); path != "" {
		c.ASNDBPath = path
	}
	c.MaxTargets = envInt("ROUTE_MAX_TARGETS", c.MaxTargets, 1, 100)
	c.MaxAttempts = envInt("ROUTE_MAX_ATTEMPTS", c.MaxAttempts, 1, 200)
	c.HourlyAttempts = envInt("ROUTE_HOURLY_ATTEMPTS", c.HourlyAttempts, 1, 200)
	c.MaxSnapshots = envInt("ROUTE_MAX_SNAPSHOTS", c.MaxSnapshots, 1, 100)
	c.MaxBytes = envInt("ROUTE_MAX_BYTES", c.MaxBytes, 65536, 16*1024*1024)
	return c
}

type probePlan struct {
	Method     string
	Sequence   uint32
	SourcePort int
}

func probeMethods(t target) []string {
	if t.Protocol == "udp" {
		// Bookworm 20211212 loses UDPv6 Paris reply correlation in the shipped
		// Linux namespace fixture. Use the qualified approximation, never a
		// futile automatic UDP pass. The diagnostic can still compare it.
		if family(t) == "ipv6" {
			return []string{"icmp-paris"}
		}
		return []string{"udp-paris", "icmp-paris"}
	}
	return []string{"tcp", "icmp-paris"}
}
func envInt(name string, fallback, minValue, maxValue int) int {
	if n, e := strconv.Atoi(os.Getenv(name)); e == nil && n >= minValue && n <= maxValue {
		return n
	}
	return fallback
}

type prober interface {
	Run(context.Context, target, probePlan) snapshot
}

func date(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
