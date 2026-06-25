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
