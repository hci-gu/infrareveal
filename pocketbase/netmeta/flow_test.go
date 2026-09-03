package netmeta

import (
	"net/netip"
	"testing"
)

func TestFlowTupleKeyPreservesPersistedFormat(t *testing.T) {
	tests := []struct {
		name       string
		protocol   string
		clientIP   string
		clientPort int
		remoteIP   string
		remotePort int
		want       string
	}{
		{"ipv4 tcp", "TCP", "10.0.0.50", 53000, "93.184.216.34", 443, "tcp|10.0.0.50|53000|93.184.216.34|443"},
		{"ipv4 udp", " udp ", "10.0.0.50", 49000, "1.1.1.1", 443, "udp|10.0.0.50|49000|1.1.1.1|443"},
		{"ipv6", "udp", "fd00::50", 53000, "2606:4700:4700::1111", 443, "udp|fd00::50|53000|2606:4700:4700::1111|443"},
		{"icmp compatibility", "icmp", "10.0.0.50", 0, "8.8.8.8", 0, "icmp|10.0.0.50|0|8.8.8.8|0"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			tuple, ok := ParseFlowTuple(test.protocol, test.clientIP, test.clientPort, test.remoteIP, test.remotePort)
			if !ok || tuple.Key() != test.want {
				t.Fatalf("got ok=%v key=%q, want %q", ok, tuple.Key(), test.want)
			}
		})
	}
}

func TestFlowTupleCanonicalizesMappedIPv4(t *testing.T) {
	tuple, ok := NewFlowTuple("TCP", netip.MustParseAddr("::ffff:10.0.0.50"), 53000, netip.MustParseAddr("::ffff:93.184.216.34"), 443)
	if !ok || tuple.Key() != "tcp|10.0.0.50|53000|93.184.216.34|443" {
		t.Fatalf("unexpected tuple: %#v", tuple)
	}
}

func TestFlowTupleRejectsInvalidTransportDestinations(t *testing.T) {
	for _, protocol := range []string{"tcp", "udp"} {
		if tuple, ok := ParseFlowTuple(protocol, "10.0.0.50", 53000, "93.184.216.34", 0); ok || tuple.Key() != "" {
			t.Fatalf("expected invalid %s tuple, got %#v", protocol, tuple)
		}
	}
	if _, ok := ParseFlowTuple("sctp", "10.0.0.50", 1, "93.184.216.34", 2); ok {
		t.Fatal("expected unsupported protocol to be rejected")
	}
}
