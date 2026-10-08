// Package packetfixture builds independent packet bytes for parser tests.
package packetfixture

import (
	"encoding/binary"
	"net/netip"
)

func IPv4TCP(source, destination string, sourcePort, destinationPort uint16, payload []byte, flags byte, headerLength int) []byte {
	transport := make([]byte, headerLength+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	transport[12] = byte(headerLength/4) << 4
	transport[13] = flags
	copy(transport[headerLength:], payload)
	return ipv4(source, destination, 6, transport)
}

func IPv4UDP(source, destination string, sourcePort, destinationPort uint16, payload []byte) []byte {
	transport := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint16(transport[0:2], sourcePort)
	binary.BigEndian.PutUint16(transport[2:4], destinationPort)
	binary.BigEndian.PutUint16(transport[4:6], uint16(len(transport)))
	copy(transport[8:], payload)
	return ipv4(source, destination, 17, transport)
}

func ipv4(source, destination string, protocol byte, transport []byte) []byte {
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
