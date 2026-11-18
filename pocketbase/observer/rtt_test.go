package observer

import (
	"testing"
	"time"

	"myapp/data"
	"myapp/netmeta"
)

func timedPacket(protocol string, micros int64, direction Direction, flags uint16, port int) PacketActivityEvent {
	tuple, _ := netmeta.ParseFlowTuple(protocol, "10.0.0.100", port, "151.101.3.6", 443)
	return PacketActivityEvent{Tuple: tuple, FlowKey: tuple.Key(), ObservedAt: time.UnixMicro(micros), Direction: direction, Protocol: protocol, WireBytes: 60, TCPFlags: flags}
}

func rttOf(chunks []data.TrafficChunk) (int64, string) {
	var merged data.TrafficChunk
	for _, c := range chunks {
		merged.MergeRTT(c.RTTUS, c.RTTSource)
	}
	return merged.RTTUS, merged.RTTSource
}

func TestTCPHandshakeRoundTrip(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(timedPacket("tcp", 100_000_000, ClientToRemote, tcpFlagSYN, 40000), "network", d)
	a.packet(timedPacket("tcp", 100_023_500, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", d)
	a.packet(timedPacket("tcp", 100_024_000, ClientToRemote, tcpFlagACK, 40000), "network", d)
	// Later packets on the same connection never re-time it.
	a.packet(timedPacket("tcp", 100_900_000, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", d)
	if rtt, source := rttOf(a.snapshot(100_950)); rtt != 23_500 || source != "tcp" {
		t.Fatalf("rtt = %d %q, want 23500 tcp", rtt, source)
	}
}

func TestRetransmittedSYNIsAmbiguous(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(timedPacket("tcp", 100_000_000, ClientToRemote, tcpFlagSYN, 40000), "network", d)
	a.packet(timedPacket("tcp", 101_000_000, ClientToRemote, tcpFlagSYN, 40000), "network", d)
	a.packet(timedPacket("tcp", 101_020_000, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", d)
	if rtt, _ := rttOf(a.snapshot(101_100)); rtt != 0 {
		t.Fatalf("Karn's rule: retransmitted SYN must not be timed, got %d", rtt)
	}
}

func TestConnectionJoinedMidStreamIsNotTimed(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(timedPacket("tcp", 100_000_000, ClientToRemote, tcpFlagACK, 40000), "network", d)
	a.packet(timedPacket("tcp", 100_010_000, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", d)
	if rtt, _ := rttOf(a.snapshot(100_100)); rtt != 0 {
		t.Fatalf("SYN-ACK without a recorded SYN must not be timed, got %d", rtt)
	}
}

func TestLowestRoundTripWinsAndTCPOutranksUDP(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	// UDP first reply (an upper bound) arrives first and is fastest.
	a.packet(timedPacket("udp", 100_000_000, ClientToRemote, 0, 50000), "network", d)
	a.packet(timedPacket("udp", 100_005_000, RemoteToClient, 0, 50000), "network", d)
	for i, rtt := range []int64{31_000, 24_000, 40_000} {
		port := 40000 + i
		at := int64(100_100_000 + i*100_000)
		a.packet(timedPacket("tcp", at, ClientToRemote, tcpFlagSYN, port), "network", d)
		a.packet(timedPacket("tcp", at+rtt, RemoteToClient, tcpFlagSYN|tcpFlagACK, port), "network", d)
	}
	if rtt, source := rttOf(a.snapshot(100_600)); rtt != 24_000 || source != "tcp" {
		t.Fatalf("rtt = %d %q, want lowest TCP 24000", rtt, source)
	}
}

func TestUDPFirstReplyIsAnUpperBound(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(timedPacket("udp", 100_000_000, ClientToRemote, 0, 50000), "network", d)
	a.packet(timedPacket("udp", 100_001_000, ClientToRemote, 0, 50000), "network", d)
	a.packet(timedPacket("udp", 100_042_000, RemoteToClient, 0, 50000), "network", d)
	if rtt, source := rttOf(a.snapshot(100_100)); rtt != 42_000 || source != "udp" {
		t.Fatalf("rtt = %d %q, want 42000 udp from the first datagram", rtt, source)
	}
	// A server-initiated UDP flow has no client opening to time.
	b := testAggregate()
	b.packet(timedPacket("udp", 100_000_000, RemoteToClient, 0, 50001), "network", d)
	if rtt, _ := rttOf(b.snapshot(100_100)); rtt != 0 {
		t.Fatalf("server-initiated UDP must not be timed, got %d", rtt)
	}
}

func TestGateHeldClientsAreNotTimed(t *testing.T) {
	a := testAggregate()
	a.timingSuppressed = func(ip string) bool { return ip == "10.0.0.100" }
	d := testDestination()
	a.packet(timedPacket("tcp", 100_000_000, ClientToRemote, tcpFlagSYN, 40000), "network", d)
	a.packet(timedPacket("tcp", 100_020_000, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", d)
	chunks := a.snapshot(100_100)
	if rtt, _ := rttOf(chunks); rtt != 0 {
		t.Fatalf("held client timed: %d", rtt)
	}
	if totals(chunks)[0] == 0 {
		t.Fatal("suppressing timing must not drop traffic")
	}
}

func TestImplausibleRoundTripsAreDiscarded(t *testing.T) {
	var timing handshakeTiming
	timing.observe("tcp", ClientToRemote, tcpFlagSYN, 100, true)
	if rtt, _ := timing.observe("tcp", RemoteToClient, tcpFlagSYN|tcpFlagACK, 100+maxRTTMicros+1, false); rtt != 0 {
		t.Fatalf("stalled handshake timed: %d", rtt)
	}
}

func TestRoundTripPersistsAndReadsBack(t *testing.T) {
	app, a, d := captureApp(t)
	destination := testDestination()
	a.packet(timedPacket("tcp", 100_000_000, ClientToRemote, tcpFlagSYN, 40000), "network", destination)
	a.packet(timedPacket("tcp", 100_018_250, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40000), "network", destination)
	commitAggregate(t, app, a, d, 100_100)
	chunks, err := data.ReadTraffic(app.DB().Select("*").From("traffic_chunks"))
	if err != nil {
		t.Fatal(err)
	}
	if rtt, source := rttOf(chunks); rtt != 18_250 || source != "tcp" {
		t.Fatalf("stored rtt = %d %q, want 18250 tcp", rtt, source)
	}
	// A later, faster handshake in the same unsealed chunk updates the stored row.
	a.packet(timedPacket("tcp", 100_200_000, ClientToRemote, tcpFlagSYN, 40001), "network", destination)
	a.packet(timedPacket("tcp", 100_211_000, RemoteToClient, tcpFlagSYN|tcpFlagACK, 40001), "network", destination)
	commitAggregate(t, app, a, d, 100_300)
	chunks, err = data.ReadTraffic(app.DB().Select("*").From("traffic_chunks"))
	if err != nil {
		t.Fatal(err)
	}
	if rtt, _ := rttOf(chunks); rtt != 11_000 {
		t.Fatalf("updated rtt = %d, want 11000", rtt)
	}
}
