package observer

import (
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
	if scope.ClientPrefix != "" && !strings.HasPrefix(clientIP, scope.ClientPrefix) {
		return false
	}
	if clientIP == scope.GatewayIP || destinationIP == scope.GatewayIP {
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

func isPublicDestination(value string) bool {
	ip, err := netip.ParseAddr(value)
	if err != nil {
		return false
	}
	return !ip.IsPrivate() &&
		!ip.IsLoopback() &&
		!ip.IsLinkLocalUnicast() &&
		!ip.IsLinkLocalMulticast() &&
		!ip.IsMulticast() &&
		!ip.IsUnspecified()
}

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
