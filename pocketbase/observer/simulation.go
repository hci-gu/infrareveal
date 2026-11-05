package observer

import (
	"context"
	"encoding/binary"
	"fmt"
	"math"
	"net/netip"
	"time"

	"github.com/pocketbase/pocketbase"
	"myapp/data"
)

const SimulationLanes = 144

// NewSimulation replaces only the capture sources and local geography lookup.
// Frames still pass through the normal parser, bounded queue, DNS attribution,
// aggregation, capture persistence and block projection. No sockets, probes,
// host accounting settings or real capture resources are used.
func NewSimulation(app *pocketbase.PocketBase, session string, expires time.Time, diagnostics bool) *Runtime {
	scope := simulationScope()
	r := New(app, nil, Config{Scope: scope, Diagnostics: diagnostics}, func() string { return session }, nil, nil)
	lanes := simulationLanes(session)
	destinations := make(map[string]data.Destination, len(lanes))
	for _, lane := range lanes {
		destinations[lane.ip] = lane.destination
	}
	r.destination = func(ip string, at time.Time) data.Destination {
		d := destinations[ip]
		d.ObservedMS = at.UnixMilli()
		return d
	}
	r.source = func(parent context.Context, send func(sourceEvent, bool)) {
		ctx, cancel := context.WithDeadline(parent, expires)
		defer cancel()
		start := time.Now()
		send(sourceEvent{at: start, status: "complete"}, false)
		for i, lane := range lanes {
			// Use the same dnsmasq line parser and correlation as live DNS.
			for _, line := range []string{
				fmt.Sprintf("dnsmasq[1]: %d %s/53000 query[A] %s from %s", i+1, lane.client, lane.domain, lane.client),
				fmt.Sprintf("dnsmasq[1]: %d %s/53000 reply %s is %s", i+1, lane.client, lane.domain, lane.ip),
			} {
				if event, ok := parseDNSMasqLine(line); ok {
					send(sourceEvent{at: start, dns: &event}, false)
				}
			}
		}
		ticker := time.NewTicker(50 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case at := <-ticker.C:
				if !at.Before(expires) || ctx.Err() != nil {
					return
				}
				elapsed := at.Sub(start).Seconds()
				for i, lane := range lanes {
					sent, received := simulationPackets(i, elapsed)
					for direction, count := range []int{sent, received} {
						for packet := 0; packet < count; packet++ {
							frame := lane.frames[direction]
							if event, ok := ParsePacketActivityFrame(frame, len(frame), at, scope); ok {
								send(sourceEvent{at: at, packet: &event}, true)
							}
						}
					}
				}
				// Ordered after this tick's packets; confirms bins through now.
				send(sourceEvent{at: at, status: "heartbeat"}, false)
			}
		}
	}
	return r
}

func simulationScope() ObservationScope {
	scope := NewObservationScope("10.254.0.0/24", "10.254.0.1")
	scope.syntheticDestinations = netip.MustParsePrefix("203.0.113.0/24")
	return scope
}

type simulationLane struct {
	client, ip, domain string
	frames             [2][]byte
	destination        data.Destination
}

// Distinct registrable names keep activity attribution and client/service lanes
// realistic without impersonating traffic actually observed from a provider.
var simulationServices = []string{
	"video", "music", "meeting", "cloud",
	"photos", "code", "news", "search",
	"shop", "chat", "mail", "docs",
	"maps", "games", "updates", "metrics",
	"calendar", "storage",
}

type simulationPlace struct {
	country, code, city string
	lat, lon            float64
}

var simulationPlaces = []simulationPlace{
	{"Sweden", "SE", "Stockholm", 59.33, 18.07},
	{"Germany", "DE", "Frankfurt", 50.11, 8.68},
	{"Netherlands", "NL", "Amsterdam", 52.37, 4.90},
	{"United Kingdom", "GB", "London", 51.51, -0.13},
	{"France", "FR", "Paris", 48.86, 2.35},
	{"Ireland", "IE", "Dublin", 53.35, -6.26},
	{"United States", "US", "Ashburn", 39.04, -77.49},
	{"United States", "US", "San Francisco", 37.77, -122.42},
	{"Canada", "CA", "Toronto", 43.65, -79.38},
	{"Brazil", "BR", "São Paulo", -23.55, -46.63},
	{"Japan", "JP", "Tokyo", 35.68, 139.69},
	{"Singapore", "SG", "Singapore", 1.35, 103.82},
	{"Australia", "AU", "Sydney", -33.87, 151.21},
	{"South Africa", "ZA", "Cape Town", -33.92, 18.42},
}

func simulationLanes(session string) []simulationLane {
	lanes := make([]simulationLane, SimulationLanes)
	for i := range lanes {
		client := fmt.Sprintf("10.254.0.%d", 10+i/len(simulationServices))
		ip := fmt.Sprintf("203.0.113.%d", i+1) // documentation-only addresses
		// Each service uses its own registrable .test domain.
		domain := simulationServices[i%len(simulationServices)] + "-demo.test"
		place := simulationPlaces[(i*7+i/len(simulationServices))%len(simulationPlaces)]
		d := data.Destination{IP: ip, Version: "simulation-" + session, Country: place.country, CountryCode: place.code, City: place.city, Lat: &place.lat, Lon: &place.lon, AccuracyKM: 25, Precision: "city", Provider: "Simulated location"}
		d.ID = data.ID(ip, d.Version)
		if i%19 == 0 {
			d.Country, d.CountryCode, d.City, d.Precision = "", "", "", "unknown"
			d.Lat, d.Lon = nil, nil
		}
		lanes[i] = simulationLane{client: client, ip: ip, domain: domain, destination: d,
			frames: [2][]byte{simulationFrame(i, client, ip, false), simulationFrame(i, client, ip, true)}}
	}
	return lanes
}

// Fixed profiles are reproducible relative to start. Every lane appears during
// the first 12 seconds, then shifts between long idle periods and shaped bursts.
// Different phases prevent an artificial all-on/all-off dashboard.
func simulationPackets(lane int, seconds float64) (sent, received int) {
	start := float64(lane%24) * 0.45
	if seconds < start {
		return 0, 0
	}
	if seconds < start+0.4 {
		return 2, 5
	}
	t := seconds - start
	phase := math.Mod(t+float64(lane*13), 72)
	wave := 0.55 + 0.45*math.Sin(t*2.4+float64(lane))
	switch lane % 18 {
	case 0, 1: // buffered media segments
		if phase < 42 && math.Mod(t, 4) < 1.4 {
			return 1, 8 + int(18*wave)
		}
	case 2: // bidirectional video calls
		if phase < 36 {
			return 3 + int(4*wave), 4 + int(6*wave)
		}
	case 3, 4, 17: // cloud/photo uploads and backups
		if phase < 10 {
			return 4 + int(22*math.Sin(phase/10*math.Pi)), 1
		}
	case 14: // larger software downloads
		if phase < 7 {
			return 1, 12 + int(24*wave)
		}
	default: // browsing, messages, API polls: mostly quiet
		if phase < 2.5 {
			return 1, 2 + int(9*math.Sin(phase/2.5*math.Pi))
		}
	}
	return 0, 0
}

// Full synthetic Ethernet/IPv4 transport frames exercise the production packet
// parser; zero-filled payload is neither inspected nor persisted.
func simulationFrame(lane int, client, remote string, incoming bool) []byte {
	udp := lane%18 <= 2
	header := 20
	if udp {
		header = 8
	}
	payload := 1250
	if !incoming && lane%18 != 2 && lane%18 != 3 && lane%18 != 4 && lane%18 != 17 {
		payload = 96
	}
	frame := make([]byte, 14+20+header+payload)
	copy(frame[:6], []byte{2, 0, 0, 0, 0, 1})
	copy(frame[6:12], []byte{2, 0, 0, 0, 1, byte(10 + lane/18)})
	binary.BigEndian.PutUint16(frame[12:14], 0x0800)
	ip := frame[14:]
	ip[0], ip[8], ip[9] = 0x45, 64, 6
	if udp {
		ip[9] = 17
	}
	binary.BigEndian.PutUint16(ip[2:4], uint16(len(ip)))
	source, destination := netip.MustParseAddr(client).As4(), netip.MustParseAddr(remote).As4()
	sourcePort, destinationPort := uint16(40000+lane), uint16(443)
	if incoming {
		source, destination = destination, source
		sourcePort, destinationPort = destinationPort, sourcePort
		copy(frame[:6], frame[6:12])
		copy(frame[6:12], []byte{2, 0, 0, 0, 0, 1})
	}
	copy(ip[12:16], source[:])
	copy(ip[16:20], destination[:])
	transport := ip[20:]
	binary.BigEndian.PutUint16(transport[:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	if udp {
		binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	} else {
		transport[12], transport[13] = 0x50, 0x18
	}
	return frame
}
