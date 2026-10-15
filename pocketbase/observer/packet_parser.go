package observer

import (
	"encoding/binary"
	"net"
	"net/netip"
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
	Tuple        netmeta.FlowTuple
	ClientMAC    string
	ObservedAt   time.Time
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
		return scope.ContainsClient(address.String())
	})
	if err != nil || !scope.Includes(packet.Protocol, tuple.ClientIP.String(), tuple.RemoteIP.String(), int(tuple.RemotePort)) {
		return PacketActivityEvent{}, false
	}
	return PacketActivityEvent{
		Tuple:        tuple,
		ClientMAC:    packetClientMAC(frame, direction),
		ObservedAt:   observedAt,
		FlowKey:      tuple.Key(),
		Direction:    direction,
		Protocol:     packet.Protocol,
		WireBytes:    uint32(wireLength),
		PayloadBytes: packet.PayloadBytes,
		TCPFlags:     packet.TCPFlags,
	}, true
}

func packetClientMAC(frame []byte, direction Direction) string {
	mac := frame[6:12]
	if direction == RemoteToClient {
		mac = frame[:6]
	}
	if mac[0]&1 != 0 || string(mac) == string(make([]byte, 6)) {
		return ""
	}
	return net.HardwareAddr(mac).String()
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
