// Package routing owns route demand, bounded probing, persistent reuse and
// immutable session evidence. It never intercepts client traffic.
package routing

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"
)

type Flow struct {
	Baseline                  bool
	ID, Session, IP, Protocol string
	Port                      int
	Bytes                     int64
	At                        time.Time
}
type HopReply struct {
	Extensions  json.RawMessage `json:"extensions,omitempty"`
	Address     string          `json:"address"`
	RTT         *float64        `json:"rtt_ms,omitempty"`
	ReportedRTT *float64        `json:"reported_rtt_ms,omitempty"`
	ProbeID     int             `json:"probe_id"`
	ICMPType    *int            `json:"icmp_type,omitempty"`
	ICMPCode    *int            `json:"icmp_code,omitempty"`
	TCPFlags    *int            `json:"tcp_flags,omitempty"`
	SeenAt      string          `json:"seen_at,omitempty"`
}
type Hop struct {
	EndTTL     int                          `json:"end_ttl,omitempty"`
	Evidence   map[string]InterfaceEvidence `json:"interface_evidence,omitempty"`
	Replies    []HopReply                   `json:"replies,omitempty"`
	TTL        int                          `json:"ttl"`
	Address    string                       `json:"address"`
	Missing    bool                         `json:"missing"`
	State      string                       `json:"state"`
	Timings    []float64                    `json:"timings"`
	Annotation string                       `json:"annotation,omitempty"`
	City       string                       `json:"city,omitempty"`
	Country    string                       `json:"country,omitempty"`
	Lat        *float64                     `json:"lat,omitempty"`
	Lon        *float64                     `json:"lon,omitempty"`
	AccuracyKM uint16                       `json:"accuracy_km,omitempty"`
	GeoVersion string                       `json:"geo_version,omitempty"`
}
type Location struct {
	Lat        float64 `json:"lat"`
	Lon        float64 `json:"lon"`
	City       string  `json:"city,omitempty"`
	Country    string  `json:"country,omitempty"`
	AccuracyKM uint16  `json:"accuracy_km,omitempty"`
	GeoVersion string  `json:"geo_version,omitempty"`
}
type target struct {
	IP, Protocol string
	Port         int
}

// A binding keeps the source context and the observed endpoint together across
// admission, a running probe, publication retries, and cache reuse.
type routeBinding struct {
	Session string
	Network string
	Target  target
}

func (b routeBinding) key() string { return b.Target.key(b.Network) }

type publication struct {
	Binding    routeBinding
	Snapshot   snapshot
	Cache      cacheEntry
	Provenance string
}

func (t target) binding() string           { return fmt.Sprintf("%s|%s|%d", t.IP, t.Protocol, t.Port) }
func (t target) method() string            { return fmt.Sprintf("%s:%d", t.Protocol, t.Port) }
func (t target) key(network string) string { return hash(network + "|v2|" + t.binding()) }
func hash(s string) string                 { v := sha256.Sum256([]byte(s)); return hex.EncodeToString(v[:]) }

type snapshot struct {
	StopReason    string    `json:"stop_reason,omitempty"`
	SourceIP      string    `json:"source_ip,omitempty"`
	EngineVersion string    `json:"engine_version,omitempty"`
	Engine        string    `json:"engine,omitempty"`
	Profile       string    `json:"profile,omitempty"`
	FlowID        string    `json:"flow_id,omitempty"`
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
	ObservationID string    `json:"observation_id"`
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

// Only accepted evidence is reusable. Older JSON may contain obsolete retry
// state; decoding deliberately ignores it without changing the retained snapshot.
type cacheEntry struct {
	Best       snapshot  `json:"best"`
	FreshUntil time.Time `json:"fresh_until"`
	ValidUntil time.Time `json:"valid_until"`
}
type Config struct {
	MaxPending                                                                                  int
	Interval, ProbeDeadline, FreshTTL, StaleTTL                                                 time.Duration
	Engine                                                                                      string
	ASNDBPath                                                                                   string
	MaxTargets, MaxAttempts, HourlyAttempts, ManualAttempts, MaxSnapshots, MaxUpdates, MaxBytes int
	MinBytes                                                                                    int64
	Cooldown                                                                                    time.Duration
}

func defaultConfig() Config {
	return Config{MaxPending: 256, Interval: 250 * time.Millisecond,
		ProbeDeadline: 45 * time.Second, FreshTTL: 10 * time.Minute, StaleTTL: time.Hour,
		Engine: "v2", ASNDBPath: "./geoip/asn.mmdb", MaxTargets: 20, MaxAttempts: 40,
		HourlyAttempts: 40, ManualAttempts: 10,
		MaxSnapshots: 100, MaxUpdates: 100, MaxBytes: 16 * 1024 * 1024,
		MinBytes: 1024 * 1024, Cooldown: 30 * time.Minute}
}

func ConfigFromEnv() Config {
	c := defaultConfig()
	if engine := os.Getenv("ROUTE_ENGINE"); engine == "legacy" || engine == "off" {
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
func (s snapshot) located() int {
	n := 0
	for _, h := range s.Hops {
		if h.Lat != nil && h.Lon != nil {
			n++
		}
	}
	return n
}
func (s snapshot) coverage() float64 {
	n := s.ProbedTTL
	if n == 0 {
		for _, h := range s.Hops {
			if h.State != "not_probed" {
				n = max(n, h.TTL)
			}
		}
	}
	if n == 0 {
		return 0
	}
	return float64(s.replies()) / float64(n)
}
func envInt(name string, fallback, minValue, maxValue int) int {
	if n, e := strconv.Atoi(os.Getenv(name)); e == nil && n >= minValue && n <= maxValue {
		return n
	}
	return fallback
}

type prober interface {
	Run(context.Context, target, probePlan, func(snapshot)) snapshot
}

func date(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}
