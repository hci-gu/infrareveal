package observer

import (
	"testing"
	"time"
)

func TestSimulationFramesAndChangingWorkload(t *testing.T) {
	lanes := simulationLanes("synthetic")
	scope := simulationScope()
	liveScope := NewObservationScope("10.254.0.0/24", "10.254.0.1")
	if _, ok := ParsePacketActivityFrame(lanes[0].frames[0], len(lanes[0].frames[0]), time.Now(), liveScope); ok {
		t.Fatal("live capture accepted synthetic addresses")
	}
	clients, services, places := map[string]bool{}, map[string]bool{}, map[string]bool{}
	for i, lane := range lanes {
		clients[lane.client], services[lane.domain], places[lane.destination.CountryCode] = true, true, true
		for direction, frame := range lane.frames {
			packet, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), scope)
			if !ok || packet.Tuple.ClientIP.String() != lane.client || packet.Tuple.RemoteIP.String() != lane.ip || packet.PayloadBytes == 0 || packet.WireBytes != uint32(len(frame)) {
				t.Fatalf("lane %d direction %d did not survive production parsing: %+v", i, direction, packet)
			}
			if (direction == 0) != (packet.Direction == ClientToRemote) {
				t.Fatal("wrong direction")
			}
		}
		active, idle, upload, download := false, false, false, false
		for tick := 1; tick <= 3600; tick++ {
			sent, received := simulationPackets(i, float64(tick)/20)
			active = active || sent+received > 0
			idle = idle || sent+received == 0
			upload = upload || sent > received
			download = download || received > sent
		}
		if !active || !idle || !download {
			t.Fatalf("lane %d lacks changing traffic", i)
		}
		if i%18 == 3 && !upload {
			t.Fatal("backup never uploads")
		}
	}
	if len(lanes) != 144 || len(clients) != 8 || len(services) != 18 || len(places) < 10 {
		t.Fatalf("insufficient variety: %d/%d/%d/%d", len(lanes), len(clients), len(services), len(places))
	}
}

func TestSimulationHandshakesProducePassiveRoundTrips(t *testing.T) {
	lanes := simulationLanes("synthetic")
	scope := simulationScope()
	edge, far := 0, 0
	for i, lane := range lanes {
		a := testAggregate()
		start := time.UnixMilli(100_000)
		for direction, at := range []time.Time{start, start.Add(lane.rtt)} {
			packet, ok := ParsePacketActivityFrame(lane.handshake[direction], len(lane.handshake[direction]), at, scope)
			if !ok {
				t.Fatalf("lane %d handshake %d rejected by the production parser", i, direction)
			}
			a.packet(packet, "network", lane.destination)
		}
		rtt, source := rttOf(a.snapshot(101_000))
		if rtt != lane.rtt.Microseconds() || (source == "tcp") != (i%18 > 2) {
			t.Fatalf("lane %d rtt = %d %q, want %d", i, rtt, source, lane.rtt.Microseconds())
		}
		if lane.rtt < 6*time.Millisecond && lane.destination.CountryCode != "" && lane.destination.CountryCode != "SE" {
			edge++
		}
		if lane.rtt > 150*time.Millisecond {
			far++
		}
	}
	if edge == 0 || far == 0 {
		t.Fatalf("simulation should include edge-served (%d) and intercontinental (%d) round trips", edge, far)
	}
}
