package observer

// Passive round-trip timing. The gateway sits between clients and servers, so
// the time from a connection's opening packet passing the gateway to the
// server's first reply is the gateway↔server round trip; the client's Wi-Fi hop
// is excluded. Nothing is sent and no payload is read.
//
//   - TCP: client SYN → server SYN-ACK. A retransmitted SYN makes the pairing
//     ambiguous (Karn's rule), so that connection yields no sample.
//   - UDP: a new flow's first client datagram → first server datagram. Servers
//     may answer late (QUIC Retry, application think time), so this is an upper
//     bound, labelled "udp" and only preferred when no TCP sample exists.

const (
	tcpFlagSYN = 0x02
	tcpFlagACK = 0x10
	// Longer than any plausible Internet round trip; anything above is a stall.
	maxRTTMicros = 10_000_000
)

type handshakeTiming struct {
	openedMicros int64
	openings     int
	done         bool
}

// observe records one packet of the connection and returns a round-trip time
// (microseconds) and its source when this packet completes a measurement.
// fresh reports that the packet created the connection record.
func (t *handshakeTiming) observe(protocol string, direction Direction, flags uint16, atMicros int64, fresh bool) (int64, string) {
	if t.done {
		return 0, ""
	}
	switch protocol {
	case "tcp":
		syn := flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN
		synAck := flags&(tcpFlagSYN|tcpFlagACK) == tcpFlagSYN|tcpFlagACK
		switch {
		case direction == ClientToRemote && syn:
			if t.openings == 0 {
				t.openedMicros = atMicros
			}
			t.openings++
		case direction == RemoteToClient && synAck:
			t.done = true
			if t.openings == 1 {
				return roundTrip(atMicros - t.openedMicros), "tcp"
			}
		case t.openings == 0:
			// Joined mid-connection (capture started later): no handshake to time.
			t.done = true
		}
	case "udp":
		if direction == ClientToRemote {
			if t.openings == 0 {
				if !fresh {
					t.done = true
					return 0, ""
				}
				t.openedMicros = atMicros
			}
			t.openings++
			return 0, ""
		}
		t.done = true
		if t.openings > 0 {
			return roundTrip(atMicros - t.openedMicros), "udp"
		}
	default:
		t.done = true
	}
	return 0, ""
}

func roundTrip(micros int64) int64 {
	if micros <= 0 || micros > maxRTTMicros {
		return 0
	}
	return micros
}
