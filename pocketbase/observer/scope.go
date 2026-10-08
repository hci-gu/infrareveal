package observer

import (
	"myapp/netmeta"
	"net/netip"
	"strings"
)

// ObservationScope defines the boundary between connected-client internet
// traffic and gateway/local infrastructure noise.
type ObservationScope struct {
	ClientPrefix string
	GatewayIP    string
	prefixes     []netip.Prefix
	gateways     map[string]bool
}

func NewObservationScope(clientPrefix, gatewayIP string) ObservationScope {
	if clientPrefix == "" {
		clientPrefix = "10.0.0."
	}
	if gatewayIP == "" {
		gatewayIP = inferredGatewayIP(clientPrefix)
	}
	scope := ObservationScope{ClientPrefix: clientPrefix, GatewayIP: gatewayIP, gateways: map[string]bool{}}
	scope.prefixes = parseClientPrefixes(clientPrefix)
	for _, gateway := range strings.Split(gatewayIP, ",") {
		scope.gateways[strings.TrimSpace(gateway)] = true
	}
	return scope
}

func (scope ObservationScope) Includes(protocol, clientIP, destinationIP string, destinationPort int) bool {
	if clientIP == "" || destinationIP == "" {
		return false
	}
	if scope.ClientPrefix != "" && !scope.ContainsClient(clientIP) {
		return false
	}
	if scope.gateways == nil {
		scope = NewObservationScope(scope.ClientPrefix, scope.GatewayIP)
	}
	if scope.gateways[clientIP] || scope.gateways[destinationIP] {
		return false
	}

	if !isPublicDestination(destinationIP) {
		return false
	}
	return !isInfrastructureFlow(protocol, destinationPort)
}

func inferredGatewayIP(clientPrefix string) string {
	if strings.HasSuffix(clientPrefix, ".") {
		return clientPrefix + "1"
	}
	return "10.0.0.1"
}

func (scope ObservationScope) ContainsClient(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	ip = ip.Unmap()
	prefixes := scope.prefixes
	if prefixes == nil {
		prefixes = parseClientPrefixes(scope.ClientPrefix)
	}
	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}
func parseClientPrefixes(value string) []netip.Prefix {
	prefixes := make([]netip.Prefix, 0)
	for _, part := range strings.Split(value, ",") {
		part = strings.TrimSpace(part)
		if strings.HasSuffix(part, ".") {
			part += "0/24"
		}
		if prefix, err := netip.ParsePrefix(part); err == nil {
			prefixes = append(prefixes, prefix)
		}
	}
	return prefixes
}

func isPublicDestination(value string) bool { return netmeta.PublicAddress(value) }

func isInfrastructureFlow(protocol string, destinationPort int) bool {
	protocol = strings.ToLower(protocol)
	if destinationPort == 53 && (protocol == "udp" || protocol == "tcp") {
		return true
	}
	if protocol != "udp" {
		return false
	}
	switch destinationPort {
	case 67, 68, 123, 5350, 5351, 5353:
		return true
	default:
		return destinationPort >= 33434 && destinationPort <= 33534
	}
}
