package observer

import (
	"context"
	"fmt"
	"github.com/pocketbase/pocketbase"
	"myapp/data"
	"sync/atomic"
	"time"
)

// NewTrafficLoad is an isolated benchmark source. It drives the real parser,
// queue, attribution, aggregation and persistence without transmitting packets.
// Packet rate and endpoint cardinality are independent controlled inputs.
func NewTrafficLoad(app *pocketbase.PocketBase, session string, expires time.Time, clients, bindings, packetsPerSecond int, meters ...*TrafficLoadMeter) *Runtime {
	var meter *TrafficLoadMeter
	if len(meters) > 0 {
		meter = meters[0]
	}
	scope := simulationScope()
	r := New(app, nil, Config{Scope: scope}, func() string { return session }, nil, nil)
	lanes := make([]simulationLane, 0, clients*bindings)
	destinations := map[string]data.Destination{}
	for client := 0; client < clients; client++ {
		for binding := 0; binding < bindings; binding++ {
			ip := fmt.Sprintf("203.0.113.%d", binding+1)
			address := fmt.Sprintf("10.254.0.%d", client+10)
			place := simulationPlaces[binding%len(simulationPlaces)]
			d := data.Destination{ID: data.ID(session, ip), IP: ip, Version: "load-" + session, Country: place.country, CountryCode: place.code, City: place.city, Lat: &place.lat, Lon: &place.lon, Precision: "city", Provider: "Synthetic load fixture"}
			if binding%19 == 0 {
				d.Lat, d.Lon = nil, nil
				d.Precision = "unknown"
			}
			destinations[ip] = d
			lanes = append(lanes, simulationLane{client: address, ip: ip, domain: fmt.Sprintf("service-%d-load.test", binding), destination: d, frames: [2][]byte{simulationFrame(client*bindings+binding, address, ip, false), simulationFrame(client*bindings+binding, address, ip, true)}})
		}
	}
	r.destination = func(ip string, at time.Time) data.Destination {
		d := destinations[ip]
		d.ObservedMS = at.UnixMilli()
		return d
	}
	r.source = func(parent context.Context, send func(sourceEvent, bool)) {
		ctx, cancel := context.WithDeadline(parent, expires)
		defer cancel()
		now := time.Now()
		if meter != nil {
			meter.StartedMS.Store(now.UnixMilli())
			defer func() { meter.EndedMS.Store(time.Now().UnixMilli()) }()
		}
		send(sourceEvent{at: now, status: "complete"}, false)
		// The isolated source knows it has supplied every event through shutdown.
		// Advance coverage past the final occupied bucket before closing the queue.
		defer func() { send(sourceEvent{at: time.Now(), status: "heartbeat"}, false) }()
		seedDNS := func(at time.Time) {
			for i, lane := range lanes {
				for _, line := range []string{fmt.Sprintf("dnsmasq[1]: %d %s/53000 query[A] %s from %s", i+1, lane.client, lane.domain, lane.client), fmt.Sprintf("dnsmasq[1]: %d %s/53000 reply %s is %s", i+1, lane.client, lane.domain, lane.ip)} {
					if event, ok := parseDNSMasqLine(line); ok {
						send(sourceEvent{at: at, dns: &event}, false)
					}
				}
			}
		}
		seedDNS(now)
		lastDNS := now
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		sequence := 0
		budget := int64(0)
		lastTick := now
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-ticker.C:
				if !at.Before(expires) || ctx.Err() != nil {
					return
				}
				if at.Sub(lastDNS) > time.Minute {
					seedDNS(at)
					lastDNS = at
				}
				// Account for missed scheduler ticks instead of quietly lowering
				// offered load when the benchmark process is busy.
				budget += at.Sub(lastTick).Nanoseconds() * int64(packetsPerSecond)
				lastTick = at
				count := int(budget / int64(time.Second))
				budget %= int64(time.Second)
				for i := 0; i < count; i++ {
					lane := lanes[sequence%len(lanes)]
					direction := (sequence / len(lanes)) % 2
					sequence++
					frame := lane.frames[direction]
					if event, ok := ParsePacketActivityFrame(frame, len(frame), at, scope); ok {
						if meter != nil {
							meter.Packets.Add(1)
							meter.WireBytes.Add(int64(event.WireBytes))
						}
						send(sourceEvent{at: at, packet: &event}, true)
					}
				}
				send(sourceEvent{at: at, status: "heartbeat"}, false)
			}
		}
	}
	return r
}

// Independent offered-load counters let the runner verify actual packet rate;
// capture's own drop counters account for queue and aggregation overflow.
type TrafficLoadMeter struct{ StartedMS, EndedMS, Packets, WireBytes atomic.Int64 }

func (m *TrafficLoadMeter) Snapshot() map[string]int64 {
	return map[string]int64{"started_ms": m.StartedMS.Load(), "ended_ms": m.EndedMS.Load(), "packets": m.Packets.Load(), "wire_bytes": m.WireBytes.Load(), "at_ms": time.Now().UnixMilli()}
}
