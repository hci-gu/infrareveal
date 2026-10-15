package observer

import (
	"encoding/json"
	"errors"
	"maps"
	"myapp/data"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	DNSLogPath, ConntrackPath, AccountingPath, LeasePath string
	SampleInterval                                       time.Duration
	Scope                                                ObservationScope
	Packet                                               PacketActivityConfig
	Diagnostics                                          bool
	NetworkEpoch                                         func() string
}

type PacketActivityConfig struct {
	Enabled                          bool
	Interface                        string
	FlushInterval                    time.Duration
	MaxPendingChunks, EventQueueSize int
}

func DefaultPolicy() data.Policy {
	p := data.Policy{BucketMS: int64(boundedEnvInt("TRAFFIC_BUCKET_MS", 50, 20, 1000)), ChunkMS: int64(boundedEnvInt("TRAFFIC_CHUNK_MS", 5000, 1000, 10000)), CorrectionMS: int64(boundedEnvInt("TRAFFIC_CORRECTION_MS", 10000, 0, 30000)), QuietGapMS: int64(boundedEnvInt("ACTIVITY_QUIET_GAP_MS", 45000, 1000, 300000)), Aliases: maps.Clone(activityDomainAliases)}
	// Chunk alignment must contain a whole number of capture bins.
	if p.ChunkMS%1000 != 0 {
		p.ChunkMS = 5000
	}
	if p.ChunkMS%p.BucketMS != 0 {
		p.BucketMS = 50
	}
	b, _ := json.Marshal(p)
	p.Version = "psl-xnet-0.58.0-" + data.ID(string(b))
	return p
}

func ConfigFromEnv(ap string) Config {
	return Config{DNSLogPath: envString("DNSMASQ_LOG_PATH", "/var/log/dnsmasq.log"), ConntrackPath: envString("CONNTRACK_PATH", "/proc/net/nf_conntrack"), AccountingPath: envString("CONNTRACK_ACCOUNTING_PATH", "/proc/sys/net/netfilter/nf_conntrack_acct"), LeasePath: envString("DHCP_LEASE_PATH", "/var/lib/infrareveal/participants.leases"), SampleInterval: time.Duration(boundedEnvInt("CONNTRACK_SAMPLE_MS", 1000, 250, 5000)) * time.Millisecond, Scope: NewObservationScope(envString("CLIENT_CIDRS", envString("CLIENT_IP_PREFIX", "10.0.0.0/24")), envString("GATEWAY_IP", "10.0.0.1")), Packet: PacketActivityConfigFromEnv(ap), Diagnostics: envBool("DIAGNOSTICS_ENABLED", false)}
}

func PacketActivityConfigFromEnv(ap string) PacketActivityConfig {
	return PacketActivityConfig{Enabled: envBool("PACKET_ACTIVITY_ENABLED", true), Interface: envString("PACKET_ACTIVITY_IFACE", ap), FlushInterval: time.Duration(boundedEnvInt("TRAFFIC_FLUSH_MS", 400, 100, 2000)) * time.Millisecond, MaxPendingChunks: boundedEnvInt("TRAFFIC_MAX_PENDING_CHUNKS", 4096, 128, 16384), EventQueueSize: boundedEnvInt("PACKET_ACTIVITY_EVENT_QUEUE", 8192, 256, 131072)}
}

func envString(name, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(name)); v != "" {
		return v
	}
	return fallback
}
func envBool(name string, fallback bool) bool {
	v, e := strconv.ParseBool(os.Getenv(name))
	if e != nil {
		return fallback
	}
	return v
}
func boundedEnvInt(name string, fallback, minimum, maximum int) int {
	v, e := strconv.Atoi(os.Getenv(name))
	if e != nil || v < minimum || v > maximum {
		return fallback
	}
	return v
}

var errPacketCaptureUnsupported = errors.New("packet capture is only supported on Linux")
