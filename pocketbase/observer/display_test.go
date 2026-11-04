package observer

import (
	"myapp/data"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestDisplayPacketsAreExcludedInBothDirectionsAndConntrack(t *testing.T) {
	scope := NewObservationScope("10.0.0.0/24", "10.0.0.1")
	scope.Excluded = func(ip, mac string) bool { return ip == "10.0.0.50" }
	for _, direction := range []bool{false, true} {
		source, dest, sp, dp := "10.0.0.50", "1.1.1.1", 53000, 443
		if direction {
			source, dest, sp, dp = dest, source, dp, sp
		}
		frame := buildIPv4TCPFrame(source, dest, sp, dp, []byte("hello"), 0x18, false)
		if _, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), scope); ok {
			t.Fatal("display packet included")
		}
	}
	line := "ipv4 2 tcp 6 100 ESTABLISHED src=10.0.0.50 dst=1.1.1.1 sport=53000 dport=443 packets=1 bytes=60 src=1.1.1.1 dst=10.0.0.50 sport=443 dport=53000 packets=1 bytes=60"
	if _, ok := parseConntrackLine(line, scope); ok {
		t.Fatal("display conntrack sample included")
	}
	scope.Excluded = nil
	if _, ok := parseConntrackLine(line, scope); !ok {
		t.Fatal("participant conntrack sample lost")
	}
}

func TestDisplayNeverReachesStoredTrafficDNSOrRouteAdmissions(t *testing.T) {
	app, a, _ := captureApp(t)
	if err := data.InstallDiagnostics(app); err != nil {
		t.Fatal(err)
	}
	scope := NewObservationScope("10.0.0.0/24", "10.0.0.1")
	scope.Excluded = func(ip, mac string) bool { return ip == "10.0.0.101" }
	var routeBytes int64
	r := New(app, nil, Config{Scope: scope, Diagnostics: true}, func() string { return a.session }, nil, func(d CommittedTraffic) { routeBytes += d.Bytes })
	now := time.Now().UnixMilli() / 50 * 50
	input := make(chan sourceEvent, 10)
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now), status: "complete"}
	participant, display := testPacket(now+100, 40000), testPacket(now+150, 40001)
	display.Tuple.ClientIP = netip.MustParseAddr("10.0.0.101")
	display.FlowKey = display.Tuple.Key()
	for _, p := range []PacketActivityEvent{participant, display} {
		input <- sourceEvent{session: a.session, at: p.ObservedAt, packet: &p}
		q := dnsLogEvent{isQuery: true, clientIP: p.Tuple.ClientIP.String(), queryName: "svt.se", queryType: "A", serial: p.FlowKey}
		input <- sourceEvent{session: a.session, at: p.ObservedAt, dns: &q}
	}
	input <- sourceEvent{session: a.session, at: time.UnixMilli(now + 250), status: "heartbeat"}
	close(input)
	var lost atomic.Int64
	if err := r.consume(input, &lost); err != nil {
		t.Fatal(err)
	}
	chunks := storedChunks(t, app)
	if len(chunks) != 1 || chunks[0].ClientIP != "10.0.0.100" || totals(chunks)[0] != 150 || routeBytes != 150 {
		t.Fatalf("display polluted observations or probing: %+v bytes=%d", chunks, routeBytes)
	}
	for _, collection := range []string{"dns_queries", "flow_diagnostics"} {
		rows, err := app.FindRecordsByFilter(collection, "client_ip='10.0.0.101'", "", 10, 0)
		if err != nil || len(rows) != 0 {
			t.Fatal("display diagnostics retained", collection, rows, err)
		}
	}
}

func TestDisplayDNSRepliesCannotUpdateEarlierParticipantQueries(t *testing.T) {
	scope := NewObservationScope("10.0.0.0/24", "10.0.0.1")
	cache := &dnsCache{}
	cache.add("session", dnsLogEvent{isQuery: true, clientIP: "10.0.0.50", serial: "42", queryName: "svt.se"}, 100000, scope)
	scope.Excluded = func(ip, mac string) bool { return ip == "10.0.0.50" }
	if updates := cache.add("session", dnsLogEvent{serial: "42", queryName: "svt.se", answer: "1.1.1.1"}, 100001, scope); len(updates) != 0 {
		t.Fatal("late display DNS reply was attributed")
	}
}
