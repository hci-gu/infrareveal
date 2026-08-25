package observer

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseConntrackLineKeepsByteAndPacketCounters(t *testing.T) {
	line := "ipv4 2 tcp 6 431999 ESTABLISHED src=10.0.0.100 dst=151.101.3.6 sport=57299 dport=443 packets=5 bytes=360 src=151.101.3.6 dst=10.0.0.100 sport=443 dport=57299 packets=7 bytes=600 [ASSURED] mark=0 zone=0 use=2"

	sample, ok := ParseConntrackLine(line, "10.0.0.")

	if !ok {
		t.Fatal("expected conntrack line to parse")
	}
	if sample.BytesOut != 360 || sample.BytesIn != 600 {
		t.Fatalf("expected byte counters 360/600, got %d/%d", sample.BytesOut, sample.BytesIn)
	}
	if sample.PacketsOut != 5 || sample.PacketsIn != 7 {
		t.Fatalf("expected packet counters 5/7, got %d/%d", sample.PacketsOut, sample.PacketsIn)
	}
}

func TestParseConntrackLineRejectsGatewayTraceroute(t *testing.T) {
	line := "ipv4 2 udp 17 29 src=10.0.0.1 dst=92.122.72.194 sport=49152 dport=33434 packets=1 bytes=60 src=92.122.72.194 dst=10.0.0.1 sport=33434 dport=49152 packets=0 bytes=0 mark=0 zone=0 use=2"

	if _, ok := ParseConntrackLine(line, "10.0.0."); ok {
		t.Fatal("expected gateway-originated traceroute to be rejected")
	}
}

func TestParseConntrackLineRejectsClientDNSFlowToGateway(t *testing.T) {
	line := "ipv4 2 udp 17 29 src=10.0.0.96 dst=10.0.0.1 sport=53001 dport=53 packets=1 bytes=72 src=10.0.0.1 dst=10.0.0.96 sport=53 dport=53001 packets=1 bytes=128 mark=0 zone=0 use=2"

	if _, ok := ParseConntrackLine(line, "10.0.0."); ok {
		t.Fatal("expected local DNS socket to be rejected because DNS is observed separately")
	}
}

func TestParseConntrackLineRejectsMulticastDiscovery(t *testing.T) {
	line := "ipv4 2 udp 17 29 src=10.0.0.96 dst=224.0.0.251 sport=5353 dport=5353 packets=3 bytes=900 src=224.0.0.251 dst=10.0.0.96 sport=5353 dport=5353 packets=0 bytes=0 mark=0 zone=0 use=2"

	if _, ok := ParseConntrackLine(line, "10.0.0."); ok {
		t.Fatal("expected multicast discovery traffic to be rejected")
	}
}

func TestParseConntrackLineRejectsInfrastructureTimeSync(t *testing.T) {
	line := "ipv4 2 udp 17 29 src=10.0.0.96 dst=17.253.38.35 sport=52120 dport=123 packets=1 bytes=76 src=17.253.38.35 dst=10.0.0.96 sport=123 dport=52120 packets=1 bytes=76 mark=0 zone=0 use=2"

	if _, ok := ParseConntrackLine(line, "10.0.0."); ok {
		t.Fatal("expected infrastructure time-sync traffic to be rejected")
	}
}

func TestParseConntrackLineKeepsRemoteClientQUIC(t *testing.T) {
	line := "ipv4 2 udp 17 29 src=10.0.0.96 dst=92.122.72.194 sport=52120 dport=443 packets=12 bytes=8000 src=92.122.72.194 dst=10.0.0.96 sport=443 dport=52120 packets=18 bytes=24000 mark=0 zone=0 use=2"

	sample, ok := ParseConntrackLine(line, "10.0.0.")
	if !ok {
		t.Fatal("expected remote client QUIC traffic to remain observable")
	}
	if sample.Protocol != "udp" || sample.DestinationPort != 443 || sample.DestinationIP != "92.122.72.194" {
		t.Fatalf("unexpected QUIC sample: %#v", sample)
	}
}

func TestEnsureConntrackAccountingEnablesDisabledFlag(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nf_conntrack_acct")
	if err := os.WriteFile(path, []byte("0\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	enabled, err := ensureConntrackAccounting(path)

	if err != nil {
		t.Fatal(err)
	}
	if !enabled {
		t.Fatal("expected accounting flag to be enabled")
	}
	value, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(value) != "1\n" {
		t.Fatalf("expected accounting flag to be 1, got %q", value)
	}
}

func TestEnsureConntrackAccountingLeavesEnabledFlagAlone(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nf_conntrack_acct")
	if err := os.WriteFile(path, []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	enabled, err := ensureConntrackAccounting(path)

	if err != nil {
		t.Fatal(err)
	}
	if enabled {
		t.Fatal("expected already-enabled accounting flag to be unchanged")
	}
}
