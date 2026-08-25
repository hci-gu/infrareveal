package observer

import "testing"

func TestObservationScopeIncludesOnlyRemoteClientTraffic(t *testing.T) {
	scope := NewObservationScope("10.0.0.", "10.0.0.1")
	tests := []struct {
		name        string
		protocol    string
		clientIP    string
		destination string
		port        int
		want        bool
	}{
		{name: "client https", protocol: "tcp", clientIP: "10.0.0.96", destination: "92.122.72.194", port: 443, want: true},
		{name: "client quic", protocol: "udp", clientIP: "10.0.0.96", destination: "92.122.72.194", port: 443, want: true},
		{name: "client stun", protocol: "udp", clientIP: "10.0.0.96", destination: "1.1.1.1", port: 3478, want: true},
		{name: "gateway source", protocol: "udp", clientIP: "10.0.0.1", destination: "92.122.72.194", port: 443, want: false},
		{name: "different source network", protocol: "tcp", clientIP: "192.168.1.20", destination: "92.122.72.194", port: 443, want: false},
		{name: "gateway destination", protocol: "udp", clientIP: "10.0.0.96", destination: "10.0.0.1", port: 5351, want: false},
		{name: "private destination", protocol: "tcp", clientIP: "10.0.0.96", destination: "192.168.1.10", port: 443, want: false},
		{name: "multicast destination", protocol: "udp", clientIP: "10.0.0.96", destination: "224.0.0.251", port: 5353, want: false},
		{name: "classic dns", protocol: "udp", clientIP: "10.0.0.96", destination: "8.8.8.8", port: 53, want: false},
		{name: "time sync", protocol: "udp", clientIP: "10.0.0.96", destination: "17.253.38.35", port: 123, want: false},
		{name: "traceroute", protocol: "udp", clientIP: "10.0.0.96", destination: "92.122.72.194", port: 33434, want: false},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := scope.Includes(test.protocol, test.clientIP, test.destination, test.port); got != test.want {
				t.Fatalf("Includes() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestIsPublicDestinationSupportsGlobalIPv6(t *testing.T) {
	if !isPublicDestination("2606:4700:4700::1111") {
		t.Fatal("expected global IPv6 destination to be observable")
	}
	for _, address := range []string{"::1", "fc00::1", "fe80::1", "ff02::fb"} {
		if isPublicDestination(address) {
			t.Fatalf("expected %s to be excluded", address)
		}
	}
}
