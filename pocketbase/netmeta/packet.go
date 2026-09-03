package netmeta

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	protocolTCP = 6
	protocolUDP = 17
)

var (
	ErrTruncatedPacket   = errors.New("truncated network packet")
	ErrMalformedPacket   = errors.New("malformed network packet")
	ErrFragmentedPacket  = errors.New("fragment cannot be associated with a transport tuple")
	ErrUnsupportedPacket = errors.New("unsupported network or transport protocol")
	ErrUnorientedPacket  = errors.New("packet does not have exactly one client endpoint")
)

type Packet struct {
	Protocol        string
	SourceIP        netip.Addr
	SourcePort      uint16
	DestinationIP   netip.Addr
	DestinationPort uint16
	IPLength        int
	PayloadBytes    uint32
	TCPFlags        uint16
}

// ParseIPPacket parses data beginning at an IPv4 or IPv6 header. It only reads
// transport headers and derives payload size from validated IP/transport lengths;
// packet payload is never retained.
func ParseIPPacket(data []byte) (Packet, error) {
	if len(data) == 0 {
		return Packet{}, ErrTruncatedPacket
	}
	switch data[0] >> 4 {
	case 4:
		return parseIPv4Packet(data)
	case 6:
		return parseIPv6Packet(data)
	default:
		return Packet{}, ErrUnsupportedPacket
	}
}

func (packet Packet) Orient(isClient func(netip.Addr) bool) (FlowTuple, Direction, error) {
	sourceClient := isClient(packet.SourceIP)
	destinationClient := isClient(packet.DestinationIP)
	if sourceClient == destinationClient {
		return FlowTuple{}, "", ErrUnorientedPacket
	}
	if sourceClient {
		tuple, ok := NewFlowTuple(packet.Protocol, packet.SourceIP, packet.SourcePort, packet.DestinationIP, packet.DestinationPort)
		if !ok {
			return FlowTuple{}, "", ErrMalformedPacket
		}
		return tuple, ClientToRemote, nil
	}
	tuple, ok := NewFlowTuple(packet.Protocol, packet.DestinationIP, packet.DestinationPort, packet.SourceIP, packet.SourcePort)
	if !ok {
		return FlowTuple{}, "", ErrMalformedPacket
	}
	return tuple, RemoteToClient, nil
}

func parseIPv4Packet(data []byte) (Packet, error) {
	if len(data) < 20 {
		return Packet{}, ErrTruncatedPacket
	}
	headerLength := int(data[0]&0x0f) * 4
	if headerLength < 20 {
		return Packet{}, ErrMalformedPacket
	}
	if len(data) < headerLength {
		return Packet{}, ErrTruncatedPacket
	}
	totalLength := int(binary.BigEndian.Uint16(data[2:4]))
	if totalLength < headerLength {
		return Packet{}, ErrMalformedPacket
	}
	fragment := binary.BigEndian.Uint16(data[6:8])
	if fragment&0x3fff != 0 {
		return Packet{}, ErrFragmentedPacket
	}
	source, ok := netip.AddrFromSlice(data[12:16])
	if !ok {
		return Packet{}, ErrMalformedPacket
	}
	destination, ok := netip.AddrFromSlice(data[16:20])
	if !ok {
		return Packet{}, ErrMalformedPacket
	}
	return parseTransportPacket(data, headerLength, totalLength, data[9], source.Unmap(), destination.Unmap())
}

func parseIPv6Packet(data []byte) (Packet, error) {
	if len(data) < 40 {
		return Packet{}, ErrTruncatedPacket
	}
	payloadLength := int(binary.BigEndian.Uint16(data[4:6]))
	ipLength := 40 + payloadLength
	nextHeader := data[6]
	transportOffset := 40

	for extensionCount := 0; extensionCount < 8; extensionCount++ {
		switch nextHeader {
		case 0, 43, 60:
			if transportOffset+2 > len(data) {
				return Packet{}, ErrTruncatedPacket
			}
			extensionLength := (int(data[transportOffset+1]) + 1) * 8
			if extensionLength < 8 || transportOffset+extensionLength > ipLength {
				return Packet{}, ErrMalformedPacket
			}
			nextHeader = data[transportOffset]
			transportOffset += extensionLength
		case 51:
			if transportOffset+2 > len(data) {
				return Packet{}, ErrTruncatedPacket
			}
			extensionLength := (int(data[transportOffset+1]) + 2) * 4
			if extensionLength < 8 || transportOffset+extensionLength > ipLength {
				return Packet{}, ErrMalformedPacket
			}
			nextHeader = data[transportOffset]
			transportOffset += extensionLength
		case 44:
			return Packet{}, ErrFragmentedPacket
		default:
			extensionCount = 8
		}
	}
	if transportOffset > ipLength {
		return Packet{}, ErrMalformedPacket
	}
	source, ok := netip.AddrFromSlice(data[8:24])
	if !ok {
		return Packet{}, ErrMalformedPacket
	}
	destination, ok := netip.AddrFromSlice(data[24:40])
	if !ok {
		return Packet{}, ErrMalformedPacket
	}
	return parseTransportPacket(data, transportOffset, ipLength, nextHeader, source.Unmap(), destination.Unmap())
}

func parseTransportPacket(data []byte, offset, ipLength int, protocolNumber byte, source, destination netip.Addr) (Packet, error) {
	if offset < 0 || ipLength < offset {
		return Packet{}, ErrMalformedPacket
	}
	if len(data) < offset+8 {
		return Packet{}, ErrTruncatedPacket
	}
	packet := Packet{
		SourceIP: source, DestinationIP: destination, IPLength: ipLength,
		SourcePort:      binary.BigEndian.Uint16(data[offset : offset+2]),
		DestinationPort: binary.BigEndian.Uint16(data[offset+2 : offset+4]),
	}
	switch protocolNumber {
	case protocolTCP:
		if len(data) < offset+20 {
			return Packet{}, ErrTruncatedPacket
		}
		headerLength := int(data[offset+12]>>4) * 4
		if headerLength < 20 || ipLength < offset+headerLength {
			return Packet{}, ErrMalformedPacket
		}
		if len(data) < offset+headerLength {
			return Packet{}, ErrTruncatedPacket
		}
		packet.Protocol = "tcp"
		packet.PayloadBytes = uint32(ipLength - offset - headerLength)
		packet.TCPFlags = uint16(data[offset+13]) | uint16(data[offset+12]&1)<<8
	case protocolUDP:
		udpLength := int(binary.BigEndian.Uint16(data[offset+4 : offset+6]))
		if udpLength < 8 || ipLength < offset+udpLength {
			return Packet{}, ErrMalformedPacket
		}
		packet.Protocol = "udp"
		packet.PayloadBytes = uint32(udpLength - 8)
	default:
		return Packet{}, ErrUnsupportedPacket
	}
	return packet, nil
}
