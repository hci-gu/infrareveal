package observer

import (
	"context"
	"myapp/data"
	"myapp/geolocation"
	"myapp/netmeta"
	"testing"
	"time"
)

func TestRememberedDNSNamesLaterConnectionsWithLowConfidence(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	answer(a, "www.svt.se", 100000)
	// The device reuses its cached answer 12 minutes later without a new lookup.
	later := int64(100000 + 12*60000)
	a.packet(testPacket(later, 40000), "network", d)
	chunks := a.snapshot(later + 50)
	if len(chunks) != 1 || chunks[0].ServiceKey != "svt.se" || chunks[0].Evidence.Source != "stale_dns" || chunks[0].Evidence.Confidence != "low" {
		t.Fatalf("remembered name not applied: %#v", chunks)
	}
	// Beyond the memory window the address is unnamed again.
	expired := later + dnsMemoryMS
	a.packet(testPacket(expired, 40001), "network", d)
	if f := a.flows[testPacket(expired, 40001).FlowKey]; f.label != d.IP {
		t.Fatalf("expired memory still named the connection: %#v", f)
	}
}

func TestConflictingRememberedNamesStayUnnamed(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	answer(a, "www.svt.se", 100000)
	answer(a, "cdn.example.org", 110000)
	later := int64(100000 + 10*60000)
	a.packet(testPacket(later, 40000), "network", d)
	if f := a.flows[testPacket(later, 40000).FlowKey]; f.label != d.IP || f.evidence.Source != "destination_ip" {
		t.Fatalf("shared address guessed from stale names: %#v", f)
	}
}

func TestNetworkOwnerNamesUnresolvedTrafficPerOwner(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	d.ASN, d.Provider = 54113, "FASTLY"
	other := d
	other.ID, other.IP = "destination0002", "151.101.3.7"
	a.packet(testPacket(100000, 40000), "network", d)
	tuple, _ := netmeta.ParseFlowTuple("tcp", "10.0.0.100", 40001, other.IP, 443)
	a.packet(PacketActivityEvent{Tuple: tuple, FlowKey: tuple.Key(), ObservedAt: time.UnixMilli(100010), Direction: ClientToRemote, WireBytes: 150, TCPFlags: 0x10}, "network", other)
	chunks := a.snapshot(100050)
	if len(chunks) != 2 {
		t.Fatalf("endpoints must stay distinct bindings: %#v", chunks)
	}
	for _, c := range chunks {
		if c.ServiceKey != "network:AS54113" || c.ServiceLabel != "Fastly network" || c.Evidence.Source != "network_owner" || c.Evidence.Confidence != "low" {
			t.Fatalf("owner fallback: %#v", c)
		}
	}
	// A DNS answer still outranks the owner within the correction tail.
	answer(a, "www.svt.se", 100100)
	for _, c := range a.snapshot(100200) {
		if c.DestinationIP == d.IP && c.ServiceKey != "svt.se" {
			t.Fatalf("DNS did not replace owner: %#v", c)
		}
	}
}

func TestAmbiguousAddressFallsBackToOwner(t *testing.T) {
	a := testAggregate()
	d := testDestination()
	d.ASN, d.Provider = 99999, "EXAMPLE-NET"
	answer(a, "www.svt.se", 100000)
	answer(a, "cdn.example.org", 100010)
	a.packet(testPacket(100100, 40000), "network", d)
	f := a.flows[testPacket(100100, 40000).FlowKey]
	if f.service != "network:AS99999" || f.label != "EXAMPLE-NET network" || !f.evidence.Ambiguous || f.evidence.Source != "ambiguous_dns" {
		t.Fatalf("ambiguous owner fallback: %#v", f)
	}
}

func TestKnownResolversAreNamedByAddressAndPort(t *testing.T) {
	for _, c := range []struct {
		protocol, ip string
		port         int
		key, label   string
	}{
		{"tcp", "1.1.1.1", 853, "resolver:encrypted:cloudflare", "Encrypted DNS · Cloudflare"},
		{"tcp", "1.0.0.1", 443, "resolver:encrypted:cloudflare", "Encrypted DNS · Cloudflare"},
		{"udp", "8.8.8.8", 53, "resolver:dns:google", "DNS · Google"},
		{"udp", "2620:fe::fe", 443, "resolver:encrypted:quad9", "Encrypted DNS · Quad9"},
	} {
		tuple, _ := netmeta.ParseFlowTuple(c.protocol, "10.0.0.100", 40000, c.ip, c.port)
		key, label, e := (&dnsCache{}).resolve("s", tuple, 1, 1, DefaultPolicy(), zeroAttribution, networkOwner{asn: 13335})
		if key != c.key || label != c.label || e.Source != "known_resolver" {
			t.Fatalf("%s:%d -> %s %s %#v", c.ip, c.port, key, label, e)
		}
	}
	tuple, _ := netmeta.ParseFlowTuple("tcp", "10.0.0.100", 40000, "1.1.1.1", 80)
	if _, ok := knownResolver(tuple); ok {
		t.Fatal("non-DNS port treated as resolver traffic")
	}
}

var zeroAttribution data.Attribution

func TestDestinationSnapshotRecordsNetworkOwner(t *testing.T) {
	geo := geolocation.OpenWithASN("../geolocation/testdata/GeoLite2-City-Test.mmdb", "../geolocation/testdata/GeoLite2-ASN-Test.mmdb", t.TempDir()+"/maxmind.json")
	defer geo.Close(context.Background())
	d := destinationSnapshot(geo, "1.128.0.1", time.UnixMilli(1))
	if d.ASN == 0 || d.Provider == "" || !ownerOf(d).ok() {
		t.Fatalf("owner missing: %#v", d)
	}
	cityOnly := geolocation.Open("../geolocation/testdata/GeoLite2-City-Test.mmdb", t.TempDir()+"/maxmind.json")
	defer cityOnly.Close(context.Background())
	if without := destinationSnapshot(cityOnly, "1.128.0.1", time.UnixMilli(1)); without.ASN != 0 || without.Version == d.Version {
		t.Fatalf("owner must be absent and versioned separately: %#v", without)
	}
}
