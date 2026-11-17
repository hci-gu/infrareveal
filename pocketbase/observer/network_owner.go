package observer

import (
	"myapp/data"
	"myapp/netmeta"
	"strconv"
	"strings"
)

// networkOwner is the autonomous system announcing a destination address. It
// names who operates the network, not which site or app a client used, so it
// is only a fallback when no DNS name identifies the connection.
type networkOwner struct {
	asn          int
	organization string
}

func ownerOf(d data.Destination) networkOwner {
	return networkOwner{asn: d.ASN, organization: d.Provider}
}

func (o networkOwner) ok() bool { return o.asn > 0 }

// One key per owner: a client's unnamed traffic to the same network shares a
// lane instead of fragmenting into one entry per CDN address.
func (o networkOwner) key() string { return "network:AS" + strconv.Itoa(o.asn) }

func (o networkOwner) label() string {
	name := knownNetworkOwners[o.asn]
	if name == "" {
		name = strings.TrimSpace(o.organization)
	}
	if name == "" {
		name = "AS" + strconv.Itoa(o.asn)
	}
	return name + " network"
}

// Registry organization names are often cryptic ("CLOUDFLARENET",
// "AMAZON-02"); well-known networks get their common name.
var knownNetworkOwners = map[int]string{
	714: "Apple", 6185: "Apple",
	15169: "Google", 396982: "Google Cloud", 19527: "Google", 36040: "YouTube", 43515: "YouTube",
	13335: "Cloudflare", 209242: "Cloudflare",
	16509: "Amazon", 14618: "Amazon",
	8075: "Microsoft", 8068: "Microsoft",
	20940: "Akamai", 16625: "Akamai", 21342: "Akamai", 33905: "Akamai",
	54113: "Fastly",
	32934: "Meta",
	2906:  "Netflix",
	32590: "Valve",
	14061: "DigitalOcean",
	16276: "OVH",
	24940: "Hetzner",
	13414: "X",
	46489: "Twitch",
	36459: "GitHub",
}

type resolverIdentity struct{ key, label string }

// Public resolvers by address. Their traffic is DNS the gateway cannot read:
// queries a client sends there never reach the gateway's own resolver.
var publicResolvers = map[string]string{
	"1.1.1.1": "Cloudflare", "1.0.0.1": "Cloudflare", "1.1.1.2": "Cloudflare", "1.0.0.2": "Cloudflare", "1.1.1.3": "Cloudflare", "1.0.0.3": "Cloudflare",
	"2606:4700:4700::1111": "Cloudflare", "2606:4700:4700::1001": "Cloudflare",
	"8.8.8.8": "Google", "8.8.4.4": "Google", "2001:4860:4860::8888": "Google", "2001:4860:4860::8844": "Google",
	"9.9.9.9": "Quad9", "149.112.112.112": "Quad9", "2620:fe::fe": "Quad9", "2620:fe::9": "Quad9",
	"208.67.222.222": "OpenDNS", "208.67.220.220": "OpenDNS",
	"94.140.14.14": "AdGuard", "94.140.15.15": "AdGuard",
}

func knownResolver(tuple netmeta.FlowTuple) (resolverIdentity, bool) {
	name := publicResolvers[tuple.RemoteIP.Unmap().String()]
	if name == "" {
		return resolverIdentity{}, false
	}
	switch tuple.RemotePort {
	case 53:
		return resolverIdentity{"resolver:dns:" + strings.ToLower(name), "DNS · " + name}, true
	case 443, 853:
		return resolverIdentity{"resolver:encrypted:" + strings.ToLower(name), "Encrypted DNS · " + name}, true
	}
	return resolverIdentity{}, false
}
