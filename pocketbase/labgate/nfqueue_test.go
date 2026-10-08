package labgate

import (
	"myapp/testsupport/packetfixture"
	"net/netip"
	"testing"
	"time"

	"myapp/netmeta"
)

func TestPacketMetadataCopiesOnlyHeaderSummary(t *testing.T) {
	packetBytes := packetfixture.IPv4TCP("10.0.0.2", "1.1.1.1", 50123, 443, make([]byte, 900), 0x02, 20)
	metadata, err := packetMetadataForMode(12, packetBytes[:40], uint32(len(packetBytes)), time.Unix(100, 0), netip.MustParsePrefix("10.0.0.0/24"), ModeFlow)
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
	if _, err := packetMetadataForMode(1, []byte{0x45}, 1, time.Now(), subnet, ModeFlow); err == nil {
		t.Fatal("truncated packet accepted")
	}
	packet := packetfixture.IPv4TCP("1.1.1.1", "8.8.8.8", 1000, 443, make([]byte, 0), 0x02, 20)
	if _, err := packetMetadataForMode(1, packet, uint32(len(packet)), time.Now(), subnet, ModeFlow); err == nil {
		t.Fatal("unoriented packet accepted")
	}
}

func TestPacketMetadataForDNSAndStrictModes(t *testing.T) {
	subnet := netip.MustParsePrefix("10.0.0.0/24")
	dns := packetfixture.IPv4UDP("10.0.0.2", "10.0.0.1", 53000, 53, make([]byte, 20))
	metadata, err := packetMetadataForMode(2, dns, uint32(len(dns)), time.Now(), subnet, ModeDNS)
	if err != nil || metadata.QueueMode != ModeDNS || metadata.Tuple.Key() != "udp|10.0.0.2|53000|10.0.0.1|53" {
		t.Fatalf("DNS metadata = %+v %v", metadata, err)
	}
	other := packetfixture.IPv4UDP("10.0.0.2", "10.0.0.1", 53000, 67, make([]byte, 20))
	if _, err := packetMetadataForMode(3, other, uint32(len(other)), time.Now(), subnet, ModeDNS); err == nil {
		t.Fatal("non-DNS traffic entered DNS mode")
	}
	inbound := packetfixture.IPv4TCP("1.1.1.1", "10.0.0.2", 443, 50123, make([]byte, 0), 0x12, 20)
	metadata, err = packetMetadataForMode(4, inbound, uint32(len(inbound)), time.Now(), subnet, ModeStrict)
	if err != nil || metadata.Direction != netmeta.RemoteToClient || metadata.Tuple.Key() != "tcp|10.0.0.2|50123|1.1.1.1|443" {
		t.Fatalf("strict inbound metadata = %+v %v", metadata, err)
	}
}
