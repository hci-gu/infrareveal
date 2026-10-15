package observer

import (
	"myapp/data"
	"myapp/netmeta"
	"testing"
	"time"
)

func testAggregate() *aggregate {
	return newAggregate("session00000001", "capture00000001", DefaultPolicy(), 256)
}
func testPacket(ms int64, sourcePort int) PacketActivityEvent {
	tuple, _ := netmeta.ParseFlowTuple("tcp", "10.0.0.100", sourcePort, "151.101.3.6", 443)
	return PacketActivityEvent{Tuple: tuple, FlowKey: tuple.Key(), ObservedAt: time.UnixMilli(ms), Direction: ClientToRemote, WireBytes: 150, PayloadBytes: 90, TCPFlags: 0x10}
}
func testDestination() data.Destination {
	return data.Destination{ID: "destination0001", IP: "151.101.3.6", Version: "test", Precision: "unknown"}
}
func answer(a *aggregate, host string, at int64) {
	scope := NewObservationScope("10.0.0.0/24", "")
	a.dns.add(a.session, dnsLogEvent{isQuery: true, queryName: host, queryType: "A", clientIP: "10.0.0.100", serial: host}, at, scope)
	a.dns.add(a.session, dnsLogEvent{queryName: host, answer: "151.101.3.6", serial: host}, at+1, scope)
}
func totals(chunks []data.TrafficChunk) (result [6]int64) {
	for _, c := range chunks {
		for _, s := range c.Samples {
			for i := range result {
				result[i] += s[i+1]
			}
		}
	}
	return
}

func TestCaptureAggregationUsesPacketsWithoutConntrack(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(testPacket(100000, 40000), "network", d)
	e := testPacket(100010, 40001)
	e.Direction = RemoteToClient
	e.WireBytes = 950
	e.PayloadBytes = 890
	a.packet(e, "network", d)
	chunks := a.snapshot(100050)
	if len(chunks) != 1 {
		t.Fatalf("source ports leaked into aggregates: %d", len(chunks))
	}
	want := [6]int64{150, 950, 90, 890, 1, 1}
	if got := totals(chunks); got != want {
		t.Fatalf("counts %v want %v", got, want)
	}
	a.conntrack([]FlowSample{{Protocol: "tcp", ClientIP: "10.0.0.100", DestinationIP: d.IP, SourcePort: 40000, DestinationPort: 443, BytesOut: 500000, BytesIn: 900000}}, 100060)
	if got := totals(a.snapshot(100100)); got != want {
		t.Fatalf("conntrack inflated counters: %v", got)
	}
	if chunks[0].ServiceLabel != d.IP || chunks[0].Evidence.Confidence != "low" {
		t.Fatal("unmatched packet must remain visible and unknown")
	}
}

func TestLateClassificationAndAmbiguityConserveBytes(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(testPacket(100000, 40000), "network", d)
	original := totals(a.snapshot(100050))
	answer(a, "www.svt.se", 100100)
	chunks := a.snapshot(100200)
	if len(chunks) != 1 || chunks[0].ServiceKey != "svt.se" {
		t.Fatalf("late DNS not applied: %#v", chunks)
	}
	if totals(chunks) != original {
		t.Fatal("classification copied/lost counters")
	}
	answer(a, "unrelated.example", 100300)
	chunks = a.snapshot(100400)
	if len(chunks) != 1 || !chunks[0].Evidence.Ambiguous || chunks[0].ServiceLabel != d.IP {
		t.Fatalf("shared endpoint not conservative: %#v", chunks)
	}
	if totals(chunks) != original {
		t.Fatal("retraction changed counters")
	}
}

func TestCorrectionHorizonFreezesEarlierLabels(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(testPacket(100000, 40000), "network", d)
	a.packet(testPacket(109000, 40000), "network", d)
	answer(a, "svt.se", 109100)
	chunks := a.snapshot(111000)
	if len(chunks) != 2 {
		t.Fatalf("need frozen unknown and corrected service: %#v", chunks)
	}
	for _, c := range chunks {
		if c.StartMS == 100000 && c.ServiceLabel != d.IP {
			t.Fatal("expired label corrected")
		}
		if c.StartMS == 105000 && c.ServiceKey != "svt.se" {
			t.Fatal("fresh label not corrected")
		}
	}
	if totals(chunks)[0] != 300 {
		t.Fatal("correction lost counts")
	}
}

func TestClientLeaseAndTupleReuseDoNotInheritEvidence(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	e := testPacket(100000, 40000)
	e.ClientMAC = "02:00:00:00:00:01"
	answer(a, "svt.se", 99900)
	a.packet(e, "network", d)
	first := a.snapshot(100050)[0]
	e.ObservedAt = time.UnixMilli(100100)
	e.ClientMAC = "02:00:00:00:00:02"
	a.packet(e, "network", d)
	chunks := a.snapshot(100150)
	if len(chunks) != 2 {
		t.Fatalf("lease identities merged: %v", chunks)
	}
	for _, c := range chunks {
		if c.ClientID != first.ClientID && c.ServiceLabel != d.IP {
			t.Fatal("new lease inherited old DNS")
		}
	}
	// A newly established connection has its own evidence; contradictory DNS is
	// not transferred from the previous connection generation.
	answer(a, "other.example", 100200)
	e.ObservedAt = time.UnixMilli(100250)
	e.TCPFlags = 0x02
	a.packet(e, "network", d)
	f := a.flows[e.FlowKey]
	if f.started != 100250 || f.service != "other.example" {
		t.Fatalf("tuple generation not reset: %#v", f)
	}
}

func TestTailCapacityReportsLossAndDoesNotBorrowConntrackBytes(t *testing.T) {
	a := testAggregate()
	a.limit = 1
	d := testDestination()
	a.packet(testPacket(100000, 40000), "network", d)
	a.packet(testPacket(100000, 40001), "network", d)
	if a.dropped != 1 || totals(a.snapshot(100050))[0] != 150 {
		t.Fatal("overflow must be explicit, retained counters exact")
	}
	answer(a, "svt.se", 100100)
	chunks := a.snapshot(100200)
	if len(chunks) != 1 || chunks[0].ServiceKey != "svt.se" {
		t.Fatal("full intake must reserve correction capacity")
	}
}

func TestNetworkEpochAndDestinationVersionKeepDistinctBindings(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	e := testPacket(100000, 40000)
	a.packet(e, "network1", d)
	a.packet(e, "network2", d)
	d.ID = "destination0002"
	a.packet(e, "network2", d)
	if chunks := a.snapshot(100050); len(chunks) != 3 || totals(chunks)[0] != 450 {
		t.Fatalf("bindings merged: %#v", chunks)
	}
}

func TestEvictedIdentityLosesDNSInsteadOfBorrowingPreviousLabel(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	answer(a, "svt.se", 99900)
	original := testPacket(100000, 40000)
	a.packet(original, "network", d)
	oldID := a.flows[original.FlowKey].id
	for port := 1; port < maxConnections; port++ {
		tuple, _ := netmeta.ParseFlowTuple("tcp", "10.0.0.100", port, "151.101.3.6", 443)
		a.flows[tuple.Key()] = &connection{id: data.ID(tuple.Key()), tuple: tuple, clientID: a.flows[original.FlowKey].clientID, started: 100100, last: 100100}
	}
	a.packet(testPacket(100200, 50000), "network", d)
	a.packet(testPacket(100250, 40000), "network", d)
	current := a.flows[original.FlowKey]
	if current.id == oldID || current.label != d.IP || current.evidence.Hostname != "" {
		t.Fatalf("evicted tuple inherited stale evidence: %#v", current)
	}
	if len(a.flows) > maxConnections || totals(a.snapshot(100300))[0] != 450 {
		t.Fatal("identity eviction affected captured counts or bound")
	}
}

func TestSYNRetryKeepsGenerationAndConntrackResetStartsAnother(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	e := testPacket(100000, 40000)
	e.TCPFlags = 0x02
	a.packet(e, "network", d)
	first := a.flows[e.FlowKey].id
	e.ObservedAt = time.UnixMilli(100100)
	a.packet(e, "network", d)
	if a.flows[e.FlowKey].id != first {
		t.Fatal("SYN retransmission invented a connection")
	}
	sample := FlowSample{Protocol: "tcp", ClientIP: e.Tuple.ClientIP.String(), DestinationIP: d.IP, SourcePort: 40000, DestinationPort: 443, BytesOut: 1000}
	a.conntrack([]FlowSample{sample}, 100150)
	sample.BytesOut = 60
	a.conntrack([]FlowSample{sample}, 100200)
	e.ObservedAt = time.UnixMilli(100250)
	a.packet(e, "network", d)
	if a.flows[e.FlowKey].id == first {
		t.Fatal("counter reset reused old identity")
	}
	if totals(a.snapshot(100300))[0] != 450 {
		t.Fatal("connection metadata changed traffic totals")
	}
}

func TestClockRollbackCannotIntroduceTrafficBehindSealedHistory(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	a.packet(testPacket(100000, 40000), "network", d)
	sealed := a.snapshot(120000)
	if len(sealed) != 1 || !sealed[0].Sealed {
		t.Fatal("expected committed sealed history")
	}
	a.committed(120000, 100000)
	// Even a new connection/binding cannot introduce a new aggregate before
	// the immutable prefix. Lost traffic must not trigger a route admission.
	a.packet(testPacket(100100, 40001), "another-network", d)
	if a.dropped != 1 || a.lossAt < 110000 || len(a.pending) != 0 || len(a.snapshot(120000)) != 0 {
		t.Fatal("backwards clock changed sealed history or hid capture loss")
	}
	a.packet(testPacket(120000, 40001), "another-network", d)
	if got := totals(a.snapshot(120050))[0]; got != 150 {
		t.Fatalf("normal capture did not resume: %d", got)
	}
}
