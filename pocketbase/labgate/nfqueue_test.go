package labgate

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"myapp/netmeta"
)

func TestPacketMetadataCopiesOnlyHeaderSummary(t *testing.T) {
	packetBytes := makeIPv4TCPPacket("10.0.0.2", "1.1.1.1", 50123, 443, 0x02, 900)
	metadata, err := packetMetadata(12, packetBytes[:40], uint32(len(packetBytes)), time.Unix(100, 0), netip.MustParsePrefix("10.0.0.0/24"))
	if err != nil {
		t.Fatal(err)
	}
	if metadata.ID != 12 || metadata.Tuple.Key() != "tcp|10.0.0.2|50123|1.1.1.1|443" || metadata.Direction != netmeta.ClientToRemote || metadata.WireBytes != uint32(len(packetBytes)) || metadata.PayloadBytes != 900 || metadata.TCPFlags != 0x02 {
		t.Fatalf("metadata = %+v", metadata)
	}
	packetBytes[20] = 0xff
	if metadata.Tuple.ClientPort != 50123 {
		t.Fatal("metadata retained packet prefix")
	}
}

func TestPacketMetadataRejectsUnorientedAndMalformed(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	if _, err := packetMetadata(1, []byte{0x45}, 1, time.Now(), subnet); err == nil {
		t.Fatal("truncated packet accepted")
	}
	packet := makeIPv4TCPPacket("1.1.1.1", "8.8.8.8", 1000, 443, 0x02, 0)
	if _, err := packetMetadata(1, packet, uint32(len(packet)), time.Now(), subnet); err == nil {
		t.Fatal("unoriented packet accepted")
	}
}

func TestPacketMetadataForDNSAndStrictModes(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	dns := makeIPv4UDPPacket("10.0.0.2", "10.0.0.1", 53000, 53, 20)
	metadata, err := packetMetadataForMode(2, dns, uint32(len(dns)), time.Now(), subnet, ModeDNS)
	if err != nil || metadata.QueueMode != ModeDNS || metadata.Tuple.Key() != "udp|10.0.0.2|53000|10.0.0.1|53" {
		t.Fatalf("DNS metadata = %+v %v", metadata, err)
	}
	other := makeIPv4UDPPacket("10.0.0.2", "10.0.0.1", 53000, 67, 20)
	if _, err := packetMetadataForMode(3, other, uint32(len(other)), time.Now(), subnet, ModeDNS); err == nil {
		t.Fatal("non-DNS traffic entered DNS mode")
	}
	inbound := makeIPv4TCPPacket("1.1.1.1", "10.0.0.2", 443, 50123, 0x12, 0)
	metadata, err = packetMetadataForMode(4, inbound, uint32(len(inbound)), time.Now(), subnet, ModeStrict)
	if err != nil || metadata.Direction != netmeta.RemoteToClient || metadata.Tuple.Key() != "tcp|10.0.0.2|50123|1.1.1.1|443" {
		t.Fatalf("strict inbound metadata = %+v %v", metadata, err)
	}
}

func makeIPv4TCPPacket(source, destination string, sourcePort, destinationPort uint16, flags byte, payloadSize int) []byte {
	packet := make([]byte, 40+payloadSize)
	packet[0], packet[9] = 0x45, 6
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	packet[32], packet[33] = 0x50, flags
	return packet
}

func makeIPv4UDPPacket(source, destination string, sourcePort, destinationPort uint16, payloadSize int) []byte {
	packet := make([]byte, 28+payloadSize)
	packet[0], packet[9] = 0x45, 17
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], netip.MustParseAddr(source).AsSlice())
	copy(packet[16:20], netip.MustParseAddr(destination).AsSlice())
	binary.BigEndian.PutUint16(packet[20:22], sourcePort)
	binary.BigEndian.PutUint16(packet[22:24], destinationPort)
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+payloadSize))
	return packet
}
