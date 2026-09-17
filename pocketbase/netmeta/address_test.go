package netmeta

import "testing"

func TestPublicAddressExcludesSpecialPurposeBothFamilies(t *testing.T) {
	for _, ip := range []string{"10.0.0.1", "100.64.0.1", "127.0.0.1", "169.254.1.1", "192.0.2.1", "198.18.0.1", "224.0.0.1", "255.255.255.255", "::", "::1", "fd00::1", "fe80::1", "ff02::1", "2001:db8::1", "::ffff:192.168.1.1", "invalid"} {
		if PublicAddress(ip) {
			t.Errorf("special address treated public: %s", ip)
		}
	}
	for _, ip := range []string{"1.1.1.1", "9.9.9.9", "2606:4700:4700::1111", "::ffff:8.8.8.8"} {
		if !PublicAddress(ip) {
			t.Errorf("public address excluded: %s", ip)
		}
	}
}
