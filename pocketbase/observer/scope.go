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
}

func NewObservationScope(clientPrefix, gatewayIP string) ObservationScope {
	if clientPrefix == "" {
		clientPrefix = "10.0.0."
	}
	if gatewayIP == "" {
		gatewayIP = inferredGatewayIP(clientPrefix)
	}
	return ObservationScope{ClientPrefix: clientPrefix, GatewayIP: gatewayIP}
}

func (scope ObservationScope) Includes(protocol, clientIP, destinationIP string, destinationPort int) bool {
	if clientIP == "" || destinationIP == "" {
		return false
	}
	if scope.ClientPrefix != "" && !scope.ContainsClient(clientIP) {
		return false
	}
	for _, gateway := range strings.Split(scope.GatewayIP, ",") {
		gateway = strings.TrimSpace(gateway)
		if clientIP == gateway || destinationIP == gateway {
			return false
		}
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
	for _, part := range strings.Split(scope.ClientPrefix, ",") {
		part = strings.TrimSpace(part)
		// Compatibility with CLIENT_IP_PREFIX=10.0.0.; internally match a CIDR.
		if strings.HasSuffix(part, ".") {
			part += "0/24"
		}
		if prefix, err := netip.ParsePrefix(part); err == nil && prefix.Contains(ip) {
			return true
		}
	}
	return false
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
