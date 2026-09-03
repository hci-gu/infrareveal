package netmeta

import (
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"
)

func TestParseIPPacketAndOrientBothDirections(t *testing.T) {
	outboundBytes := buildIPv4TCPPacket("10.0.0.50", "93.184.216.34", 53000, 443, []byte("hello"), 0x18, 24)
	outbound, err := ParseIPPacket(outboundBytes)
	if err != nil {
		t.Fatal(err)
	}
	if outbound.PayloadBytes != 5 || outbound.TCPFlags != 0x18 || outbound.IPLength != len(outboundBytes) {
		t.Fatalf("unexpected outbound packet: %#v", outbound)
	}
	tuple, direction, err := outbound.Orient(private10Client)
	if err != nil || direction != ClientToRemote || tuple.Key() != "tcp|10.0.0.50|53000|93.184.216.34|443" {
		t.Fatalf("unexpected outbound orientation: tuple=%#v direction=%s error=%v", tuple, direction, err)
	}

	inboundBytes := buildIPv4TCPPacket("93.184.216.34", "10.0.0.50", 443, 53000, make([]byte, 120), 0x10, 20)
	inbound, err := ParseIPPacket(inboundBytes)
	if err != nil {
		t.Fatal(err)
	}
	inboundTuple, inboundDirection, err := inbound.Orient(private10Client)
	if err != nil || inboundDirection != RemoteToClient || inboundTuple.Key() != tuple.Key() {
		t.Fatalf("unexpected inbound orientation: tuple=%#v direction=%s error=%v", inboundTuple, inboundDirection, err)
	}
}

func TestParseIPPacketSupportsBoundedIPv6Extensions(t *testing.T) {
	packetBytes := buildIPv6UDPWithHopByHop("fd00::50", "2606:4700:4700::1111", 54000, 443, make([]byte, 24))
	packet, err := ParseIPPacket(packetBytes)
	if err != nil {
		t.Fatal(err)
	}
	if packet.Protocol != "udp" || packet.PayloadBytes != 24 {
		t.Fatalf("unexpected packet: %#v", packet)
	}
	tuple, direction, err := packet.Orient(func(address netip.Addr) bool { return address.IsPrivate() })
	if err != nil || direction != ClientToRemote || tuple.RemotePort != 443 {
		t.Fatalf("unexpected orientation: %#v %s %v", tuple, direction, err)
	}
}

func TestParseIPPacketRejectsFragmentsAndMalformedLengths(t *testing.T) {
	fragment := buildIPv4UDPPacket("10.0.0.50", "1.1.1.1", 53000, 443, []byte("data"))
	binary.BigEndian.PutUint16(fragment[6:8], 0x2000)
	if _, err := ParseIPPacket(fragment); !errors.Is(err, ErrFragmentedPacket) {
		t.Fatalf("expected fragment error, got %v", err)
	}

	invalidUDP := buildIPv4UDPPacket("10.0.0.50", "1.1.1.1", 53000, 443, nil)
	binary.BigEndian.PutUint16(invalidUDP[20+4:20+6], 4000)
	if _, err := ParseIPPacket(invalidUDP); !errors.Is(err, ErrMalformedPacket) {
		t.Fatalf("expected malformed UDP error, got %v", err)
	}

	truncatedTCP := buildIPv4TCPPacket("10.0.0.50", "1.1.1.1", 53000, 443, nil, 0x10, 24)[:42]
	if _, err := ParseIPPacket(truncatedTCP); !errors.Is(err, ErrTruncatedPacket) {
		t.Fatalf("expected truncated TCP header error, got %v", err)
	}

	ipv6Fragment := make([]byte, 48)
	ipv6Fragment[0] = 0x60
	binary.BigEndian.PutUint16(ipv6Fragment[4:6], 8)
	ipv6Fragment[6] = 44
	copy(ipv6Fragment[8:24], netip.MustParseAddr("fd00::50").AsSlice())
	copy(ipv6Fragment[24:40], netip.MustParseAddr("2606:4700:4700::1111").AsSlice())
	if _, err := ParseIPPacket(ipv6Fragment); !errors.Is(err, ErrFragmentedPacket) {
		t.Fatalf("expected IPv6 fragment error, got %v", err)
	}
}

func TestPacketOrientationRequiresExactlyOneClient(t *testing.T) {
	packet, err := ParseIPPacket(buildIPv4UDPPacket("10.0.0.50", "10.0.0.51", 53000, 443, nil))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := packet.Orient(private10Client); !errors.Is(err, ErrUnorientedPacket) {
		t.Fatalf("expected unoriented error, got %v", err)
	}
}

func private10Client(address netip.Addr) bool {
	return address.Is4() && address.As4()[0] == 10
}

func buildIPv4TCPPacket(source, destination string, sourcePort, destinationPort uint16, payload []byte, flags byte, headerLength int) []byte {
	transport := make([]byte, headerLength+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	transport[12] = byte(headerLength/4) << 4
	transport[13] = flags
	copy(transport[headerLength:], payload)
	return buildIPv4Packet(source, destination, protocolTCP, transport)
}

func buildIPv4UDPPacket(source, destination string, sourcePort, destinationPort uint16, payload []byte) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)
	return buildIPv4Packet(source, destination, protocolUDP, transport)
}

func buildIPv4Packet(source, destination string, protocol byte, transport []byte) []byte {
	packet := make([]byte, 20+len(transport))
	packet[0] = 0x45
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	packet[8] = 64
	packet[9] = protocol
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	copy(packet[20:], transport)
	return packet
}

func buildIPv6UDPWithHopByHop(source, destination string, sourcePort, destinationPort uint16, payload []byte) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)

	packet := make([]byte, 40+8+len(transport))
	packet[0] = 0x60
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(transport)))
	packet[6] = 0
	packet[7] = 64
	copy(packet[8:24], netip.MustParseAddr(source).AsSlice())
	copy(packet[24:40], netip.MustParseAddr(destination).AsSlice())
	packet[40] = protocolUDP
	packet[41] = 0
	copy(packet[48:], transport)
	return packet
}
