package labgate

import (
	"errors"
	"net/netip"
	"time"

	"myapp/netmeta"
)

var ErrUnsupported = errors.New("NFQUEUE is unsupported on this platform")

type NFQueueConfig struct {
	QueueNumber    uint16
	MaxQueueLength uint32
	ClientSubnet   netip.Prefix
	Mode           Mode
}

func packetMetadata(packetID uint32, prefix []byte, capturedLength uint32, occurredAt time.Time, clientSubnet netip.Prefix) (QueuedPacket, error) {
	return packetMetadataForMode(packetID, prefix, capturedLength, occurredAt, clientSubnet, ModeFlow)
}

func packetMetadataForMode(packetID uint32, prefix []byte, capturedLength uint32, occurredAt time.Time, clientSubnet netip.Prefix, mode Mode) (QueuedPacket, error) {
	parsed, err := netmeta.ParseIPPacket(prefix)
	if err != nil {
		return QueuedPacket{}, err
	}
	var tuple netmeta.FlowTuple
	var direction netmeta.Direction
	if mode == ModeDNS {
		if !clientSubnet.Contains(parsed.SourceIP) || parsed.DestinationPort != 53 {
			return QueuedPacket{}, netmeta.ErrUnorientedPacket
		}
		tuple, _ = netmeta.NewFlowTuple(parsed.Protocol, parsed.SourceIP, parsed.SourcePort, parsed.DestinationIP, parsed.DestinationPort)
		direction = netmeta.ClientToRemote
	} else {
		tuple, direction, err = parsed.Orient(clientSubnet.Contains)
	}
	if err != nil {
		return QueuedPacket{}, err
	}
	wireBytes := capturedLength
	if wireBytes == 0 {
		wireBytes = uint32(parsed.IPLength)
	}
	return QueuedPacket{
		ID: packetID, QueueMode: mode, Tuple: tuple, Direction: direction, WireBytes: wireBytes,
		PayloadBytes: parsed.PayloadBytes, TCPFlags: parsed.TCPFlags, OccurredAt: occurredAt,
	}, nil
}
