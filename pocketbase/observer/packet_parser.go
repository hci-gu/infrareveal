package observer

import (
	"encoding/binary"
	"net/netip"
	"strings"
	"time"

	"myapp/netmeta"
)

const (
	etherTypeIPv4 = 0x0800
	etherTypeIPv6 = 0x86dd
	etherTypeVLAN = 0x8100
	etherTypeQinQ = 0x88a8
	protocolTCP   = 6
	protocolUDP   = 17
)

type Direction = netmeta.Direction

const (
	ClientToRemote = netmeta.ClientToRemote
	RemoteToClient = netmeta.RemoteToClient
)

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

func ParsePacketActivityFrame(frame []byte, wireLength int, observedAt time.Time, scope ObservationScope) (PacketActivityEvent, bool) {
	if wireLength < 0 {
		return PacketActivityEvent{}, false
	}
	etherType, networkOffset, ok := ethernetNetworkOffset(frame)
	if !ok {
		return PacketActivityEvent{}, false
	}

	if etherType != etherTypeIPv4 && etherType != etherTypeIPv6 {
		return PacketActivityEvent{}, false
	}
	packet, err := netmeta.ParseIPPacket(frame[networkOffset:])
	if err != nil || networkOffset+packet.IPLength > wireLength {
		return PacketActivityEvent{}, false
	}
	tuple, direction, err := packet.Orient(func(address netip.Addr) bool {
		return scope.ClientPrefix != "" && strings.HasPrefix(address.String(), scope.ClientPrefix)
	})
	if err != nil || !scope.Includes(packet.Protocol, tuple.ClientIP.String(), tuple.RemoteIP.String(), int(tuple.RemotePort)) {
		return PacketActivityEvent{}, false
	}
	return PacketActivityEvent{
		ObservedAt:   observedAt,
		FlowKey:      tuple.Key(),
		Direction:    direction,
		Protocol:     packet.Protocol,
		WireBytes:    uint32(wireLength),
		PayloadBytes: packet.PayloadBytes,
		TCPFlags:     packet.TCPFlags,
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
