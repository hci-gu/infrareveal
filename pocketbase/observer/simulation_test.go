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
