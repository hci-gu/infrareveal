package observer

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"
)

func TestParsePacketActivityNormalizesDirections(t *testing.T) {
	scope := NewObservationScope("10.0.0.", "10.0.0.1")
	now := time.Date(2026, 8, 25, 14, 0, 0, 0, time.UTC)

	outboundFrame := buildIPv4TCPFrame("10.0.0.50", "93.184.216.34", 53000, 443, []byte("hello"), 0x18, false)
	outbound, ok := ParsePacketActivityFrame(outboundFrame, len(outboundFrame), now, scope)
	if !ok {
		t.Fatal("expected outbound packet to parse")
	}
	if outbound.Direction != ClientToRemote || outbound.FlowKey != "tcp|10.0.0.50|53000|93.184.216.34|443" {
		t.Fatalf("unexpected outbound normalization: %#v", outbound)
	}
	if outbound.PayloadBytes != 5 || outbound.TCPFlags != 0x18 {
		t.Fatalf("unexpected outbound payload metadata: %#v", outbound)
	}

	inboundFrame := buildIPv4TCPFrame("93.184.216.34", "10.0.0.50", 443, 53000, make([]byte, 120), 0x18, false)
	inbound, ok := ParsePacketActivityFrame(inboundFrame, len(inboundFrame), now, scope)
	if !ok {
		t.Fatal("expected inbound packet to parse")
	}
	if inbound.Direction != RemoteToClient || inbound.FlowKey != outbound.FlowKey || inbound.PayloadBytes != 120 {
		t.Fatalf("unexpected inbound normalization: %#v", inbound)
	}
}

func TestParsePacketActivityCountsACKAsWireOnly(t *testing.T) {
	frame := buildIPv4TCPFrame("10.0.0.50", "93.184.216.34", 53000, 443, nil, 0x10, false)
	event, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), NewObservationScope("10.0.0.", "10.0.0.1"))
	if !ok {
		t.Fatal("expected ACK to parse")
	}
	if event.PayloadBytes != 0 || event.WireBytes == 0 || event.TCPFlags != 0x10 {
		t.Fatalf("expected wire-only ACK metadata, got %#v", event)
	}
}

func TestParsePacketActivityHandlesTCPOptions(t *testing.T) {
	transport := make([]byte, 24+7)
	binary.BigEndian.PutUint16(transport[0:2], 53000)
	binary.BigEndian.PutUint16(transport[2:4], 443)
	transport[12] = 6 << 4
	transport[13] = 0x18
	copy(transport[24:], []byte("payload"))
	frame := buildIPv4Frame("10.0.0.50", "93.184.216.34", protocolTCP, transport, false)
	event, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), NewObservationScope("10.0.0.", "10.0.0.1"))
	if !ok || event.PayloadBytes != 7 {
		t.Fatalf("expected TCP options to be excluded from payload, got ok=%v event=%#v", ok, event)
	}
}

func TestParsePacketActivitySupportsVLANAndUDP(t *testing.T) {
	frame := buildIPv4UDPFrame("10.0.0.50", "1.1.1.1", 53000, 443, make([]byte, 32), true)
	event, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), NewObservationScope("10.0.0.", "10.0.0.1"))
	if !ok {
		t.Fatal("expected VLAN UDP packet to parse")
	}
	if event.Protocol != "udp" || event.PayloadBytes != 32 || event.FlowKey != "udp|10.0.0.50|53000|1.1.1.1|443" {
		t.Fatalf("unexpected UDP metadata: %#v", event)
	}
}

func TestParsePacketActivityRejectsFragmentsMalformedAndInfrastructure(t *testing.T) {
	scope := NewObservationScope("10.0.0.", "10.0.0.1")
	fragment := buildIPv4UDPFrame("10.0.0.50", "1.1.1.1", 53000, 443, []byte("data"), false)
	binary.BigEndian.PutUint16(fragment[14+6:14+8], 0x2000)
	if _, ok := ParsePacketActivityFrame(fragment, len(fragment), time.Now(), scope); ok {
		t.Fatal("expected fragmented IPv4 packet to be rejected")
	}
	if _, ok := ParsePacketActivityFrame([]byte{1, 2, 3}, 3, time.Now(), scope); ok {
		t.Fatal("expected truncated Ethernet frame to be rejected")
	}
	invalidLength := buildIPv4TCPFrame("10.0.0.50", "93.184.216.34", 53000, 443, nil, 0x10, false)
	binary.BigEndian.PutUint16(invalidLength[14+2:14+4], 4000)
	if _, ok := ParsePacketActivityFrame(invalidLength, len(invalidLength), time.Now(), scope); ok {
		t.Fatal("expected an IP length larger than the wire packet to be rejected")
	}
	dns := buildIPv4UDPFrame("10.0.0.50", "8.8.8.8", 53000, 53, []byte("dns"), false)
	if _, ok := ParsePacketActivityFrame(dns, len(dns), time.Now(), scope); ok {
		t.Fatal("expected infrastructure DNS traffic to be rejected")
	}
}

func TestParsePacketActivitySupportsBasicIPv6(t *testing.T) {
	frame := buildIPv6UDPFrame("fd00::50", "2606:4700:4700::1111", 53000, 443, make([]byte, 24))
	event, ok := ParsePacketActivityFrame(frame, len(frame), time.Now(), NewObservationScope("fd00:", "fd00::1"))
	if !ok {
		t.Fatal("expected basic IPv6 UDP packet to parse")
	}
	if event.PayloadBytes != 24 || event.Direction != ClientToRemote {
		t.Fatalf("unexpected IPv6 metadata: %#v", event)
	}
}

func buildIPv4TCPFrame(source, destination string, sourcePort, destinationPort int, payload []byte, flags byte, vlan bool) []byte {
	transport := make([]byte, 20+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(transport[2:4], uint16(destinationPort))
	transport[12] = 5 << 4
	transport[13] = flags
	copy(transport[20:], payload)
	return buildIPv4Frame(source, destination, protocolTCP, transport, vlan)
}

func buildIPv4UDPFrame(source, destination string, sourcePort, destinationPort int, payload []byte, vlan bool) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(transport[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)
	return buildIPv4Frame(source, destination, protocolUDP, transport, vlan)
}

func buildIPv4Frame(source, destination string, protocol byte, transport []byte, vlan bool) []byte {
	ethernetLength := 14
	if vlan {
		ethernetLength = 18
	}
	frame := make([]byte, ethernetLength+20+len(transport))
	if vlan {
		binary.BigEndian.PutUint16(frame[12:14], etherTypeVLAN)
		binary.BigEndian.PutUint16(frame[16:18], etherTypeIPv4)
	} else {
		binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv4)
	}
	offset := ethernetLength
	frame[offset] = 0x45
	binary.BigEndian.PutUint16(frame[offset+2:offset+4], uint16(20+len(transport)))
	frame[offset+8] = 64
	frame[offset+9] = protocol
	copy(frame[offset+12:offset+16], netip.MustParseAddr(source).AsSlice())
	copy(frame[offset+16:offset+20], netip.MustParseAddr(destination).AsSlice())
	copy(frame[offset+20:], transport)
	return frame
}

func buildIPv6UDPFrame(source, destination string, sourcePort, destinationPort int, payload []byte) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], uint16(sourcePort))
	binary.BigEndian.PutUint16(transport[2:4], uint16(destinationPort))
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)

	frame := make([]byte, 14+40+len(transport))
	binary.BigEndian.PutUint16(frame[12:14], etherTypeIPv6)
	offset := 14
	frame[offset] = 0x60
	binary.BigEndian.PutUint16(frame[offset+4:offset+6], uint16(len(transport)))
	frame[offset+6] = protocolUDP
	frame[offset+7] = 64
	copy(frame[offset+8:offset+24], netip.MustParseAddr(source).AsSlice())
	copy(frame[offset+24:offset+40], netip.MustParseAddr(destination).AsSlice())
	copy(frame[offset+40:], transport)
	return frame
}
