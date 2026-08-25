package observer

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"time"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8
	protocolTCP   = 6
	protocolUDP   = 17
)

type Direction uint8

const (
	ClientToRemote Direction = iota + 1
	RemoteToClient
)

func (direction Direction) String() string {
	if direction == RemoteToClient {
		return "remote_to_client"
	}
	return "client_to_remote"
}

type PacketActivityEvent struct {
	ObservedAt   time.Time
	SessionID    string
	FlowKey      string
	Direction    Direction
	Protocol     string
	WireBytes    uint32
	PayloadBytes uint32
	TCPFlags     uint16
}

type packetTuple struct {
	sourceIP        string
	destinationIP   string
	sourcePort      int
	destinationPort int
	protocol        string
	payloadBytes    int
	tcpFlags        uint16
}

func ParsePacketActivityFrame(frame []byte, wireLength int, observedAt time.Time, scope ObservationScope) (PacketActivityEvent, bool) {
	if wireLength < 0 {
		return PacketActivityEvent{}, false
	}
	etherType, networkOffset, ok := ethernetNetworkOffset(frame)
	if !ok {
		return PacketActivityEvent{}, false
	}

	var tuple packetTuple
	switch etherType {
	case etherTypeIPv4:
		if len(frame) < networkOffset+4 || networkOffset+int(binary.BigEndian.Uint16(frame[networkOffset+2:networkOffset+4])) > wireLength {
			return PacketActivityEvent{}, false
		}
		tuple, ok = parseIPv4Tuple(frame, networkOffset)
	case etherTypeIPv6:
		if len(frame) < networkOffset+6 || networkOffset+40+int(binary.BigEndian.Uint16(frame[networkOffset+4:networkOffset+6])) > wireLength {
			return PacketActivityEvent{}, false
		}
		tuple, ok = parseIPv6Tuple(frame, networkOffset)
	default:
		return PacketActivityEvent{}, false
	}
	if !ok {
		return PacketActivityEvent{}, false
	}

	clientIP, remoteIP := tuple.sourceIP, tuple.destinationIP
	clientPort, remotePort := tuple.sourcePort, tuple.destinationPort
	direction := ClientToRemote
	if !isClientAddress(scope, clientIP) && isClientAddress(scope, tuple.destinationIP) {
		clientIP, remoteIP = tuple.destinationIP, tuple.sourceIP
		clientPort, remotePort = tuple.destinationPort, tuple.sourcePort
		direction = RemoteToClient
	}
	if !scope.Includes(tuple.protocol, clientIP, remoteIP, remotePort) {
		return PacketActivityEvent{}, false
	}
	return PacketActivityEvent{
		ObservedAt:   observedAt,
		FlowKey:      flowKey(tuple.protocol, clientIP, clientPort, remoteIP, remotePort),
		Direction:    direction,
		Protocol:     tuple.protocol,
		WireBytes:    uint32(wireLength),
		PayloadBytes: uint32(tuple.payloadBytes),
		TCPFlags:     tuple.tcpFlags,
	}, true
}

func ethernetNetworkOffset(frame []byte) (uint16, int, bool) {
	if len(frame) < 14 {
		return 0, 0, false
	}
	etherType := binary.BigEndian.Uint16(frame[12:14])
	offset := 14
	for etherType == etherTypeVLAN || etherType == etherTypeQinQ {
		if len(frame) < offset+4 {
			return 0, 0, false
		}
		etherType = binary.BigEndian.Uint16(frame[offset+2 : offset+4])
		offset += 4
	}
	return etherType, offset, true
}

func parseIPv4Tuple(frame []byte, offset int) (packetTuple, bool) {
	if len(frame) < offset+20 || frame[offset]>>4 != 4 {
		return packetTuple{}, false
	}
	headerLength := int(frame[offset]&0x0f) * 4
	if headerLength < 20 || len(frame) < offset+headerLength {
		return packetTuple{}, false
	}
	totalLength := int(binary.BigEndian.Uint16(frame[offset+2 : offset+4]))
	if totalLength < headerLength {
		return packetTuple{}, false
	}
	fragment := binary.BigEndian.Uint16(frame[offset+6 : offset+8])
	if fragment&0x3fff != 0 {
		return packetTuple{}, false
	}

	source, ok := netip.AddrFromSlice(frame[offset+12 : offset+16])
	if !ok {
		return packetTuple{}, false
	}
	destination, ok := netip.AddrFromSlice(frame[offset+16 : offset+20])
	if !ok {
		return packetTuple{}, false
	}
	return parseTransportTuple(
		frame,
		offset+headerLength,
		offset+totalLength,
		frame[offset+9],
		source.String(),
		destination.String(),
	)
}

func parseIPv6Tuple(frame []byte, offset int) (packetTuple, bool) {
	if len(frame) < offset+40 || frame[offset]>>4 != 6 {
		return packetTuple{}, false
	}
	payloadLength := int(binary.BigEndian.Uint16(frame[offset+4 : offset+6]))
	ipEnd := offset + 40 + payloadLength
	nextHeader := frame[offset+6]
	transportOffset := offset + 40

	for extensionCount := 0; extensionCount < 8; extensionCount++ {
		switch nextHeader {
		case 0, 43, 60:
			if len(frame) < transportOffset+2 {
				return packetTuple{}, false
			}
			extensionLength := (int(frame[transportOffset+1]) + 1) * 8
			nextHeader = frame[transportOffset]
			transportOffset += extensionLength
		case 51:
			if len(frame) < transportOffset+2 {
				return packetTuple{}, false
			}
			extensionLength := (int(frame[transportOffset+1]) + 2) * 4
			nextHeader = frame[transportOffset]
			transportOffset += extensionLength
		case 44:
			return packetTuple{}, false
		default:
			extensionCount = 8
		}
	}
	if transportOffset > ipEnd {
		return packetTuple{}, false
	}

	source, ok := netip.AddrFromSlice(frame[offset+8 : offset+24])
	if !ok {
		return packetTuple{}, false
	}
	destination, ok := netip.AddrFromSlice(frame[offset+24 : offset+40])
	if !ok {
		return packetTuple{}, false
	}
	return parseTransportTuple(frame, transportOffset, ipEnd, nextHeader, source.String(), destination.String())
}

func parseTransportTuple(frame []byte, offset, ipEnd int, protocolNumber byte, sourceIP, destinationIP string) (packetTuple, bool) {
	if ipEnd < offset || len(frame) < offset+8 {
		return packetTuple{}, false
	}
	sourcePort := int(binary.BigEndian.Uint16(frame[offset : offset+2]))
	destinationPort := int(binary.BigEndian.Uint16(frame[offset+2 : offset+4]))

	switch protocolNumber {
	case protocolTCP:
		if len(frame) < offset+20 {
			return packetTuple{}, false
		}
		headerLength := int(frame[offset+12]>>4) * 4
		if headerLength < 20 || len(frame) < offset+headerLength || ipEnd < offset+headerLength {
			return packetTuple{}, false
		}
		flags := uint16(frame[offset+13]) | uint16(frame[offset+12]&1)<<8
		return packetTuple{
			sourceIP: sourceIP, destinationIP: destinationIP,
			sourcePort: sourcePort, destinationPort: destinationPort,
			protocol: "tcp", payloadBytes: ipEnd - offset - headerLength, tcpFlags: flags,
		}, true
	case protocolUDP:
		udpLength := int(binary.BigEndian.Uint16(frame[offset+4 : offset+6]))
		if udpLength < 8 || ipEnd < offset+udpLength {
			return packetTuple{}, false
		}
		return packetTuple{
			sourceIP: sourceIP, destinationIP: destinationIP,
			sourcePort: sourcePort, destinationPort: destinationPort,
			protocol: "udp", payloadBytes: udpLength - 8,
		}, true
	default:
		return packetTuple{}, false
	}
}

func isClientAddress(scope ObservationScope, value string) bool {
	return scope.ClientPrefix != "" && len(value) >= len(scope.ClientPrefix) && value[:len(scope.ClientPrefix)] == scope.ClientPrefix
}

func flowKey(protocol, clientIP string, clientPort int, destinationIP string, destinationPort int) string {
	return fmt.Sprintf("%s|%s|%d|%s|%d", protocol, clientIP, clientPort, destinationIP, destinationPort)
}
