package netmeta

import "net/netip"

// PublicAddress is a conservative enrichment/probing policy, not a reachability
// test. Special-use addresses remain valid observations but have no public geo.
func PublicAddress(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	if !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return false
	}
	for _, p := range specialPrefixes {
		if p.Contains(ip) {
			return false
		}
	}
	return true
}

var specialPrefixes = func() []netip.Prefix {
	values := []string{"0.0.0.0/8", "100.64.0.0/10", "192.0.0.0/24", "192.0.2.0/24", "192.88.99.0/24", "198.18.0.0/15", "198.51.100.0/24", "203.0.113.0/24", "240.0.0.0/4", "::/96", "64:ff9b:1::/48", "100::/64", "2001:db8::/32", "2001:2::/48", "2001:10::/28", "2001:20::/28", "3fff::/20"}
	result := make([]netip.Prefix, 0, len(values))
	for _, v := range values {
		result = append(result, netip.MustParsePrefix(v))
	}
	return result
}()
