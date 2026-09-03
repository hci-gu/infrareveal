// Package netmeta owns the canonical network tuple used by observers, traces,
// and the optional lab gate. It intentionally contains no PocketBase or UI code.
package netmeta

import (
	"fmt"
	"net/netip"
	"strings"
)

type Direction string

const (
	ClientToRemote Direction = "client_to_remote"
	RemoteToClient Direction = "remote_to_client"
)

func (direction Direction) String() string { return string(direction) }

type FlowTuple struct {
	Protocol   string
	ClientIP   netip.Addr
	ClientPort uint16
	RemoteIP   netip.Addr
	RemotePort uint16
}

func NewFlowTuple(protocol string, clientIP netip.Addr, clientPort uint16, remoteIP netip.Addr, remotePort uint16) (FlowTuple, bool) {
	tuple := FlowTuple{
		Protocol: strings.ToLower(strings.TrimSpace(protocol)),
		ClientIP: clientIP.Unmap(), ClientPort: clientPort,
		RemoteIP: remoteIP.Unmap(), RemotePort: remotePort,
	}
	if !tuple.Valid() {
		return FlowTuple{}, false
	}
	return tuple, true
}

func ParseFlowTuple(protocol, clientIP string, clientPort int, remoteIP string, remotePort int) (FlowTuple, bool) {
	if clientPort < 0 || clientPort > 65535 || remotePort < 0 || remotePort > 65535 {
		return FlowTuple{}, false
	}
	client, err := netip.ParseAddr(strings.TrimSpace(clientIP))
	if err != nil {
		return FlowTuple{}, false
	}
	remote, err := netip.ParseAddr(strings.TrimSpace(remoteIP))
	if err != nil {
		return FlowTuple{}, false
	}
	return NewFlowTuple(protocol, client, uint16(clientPort), remote, uint16(remotePort))
}

func (tuple FlowTuple) Valid() bool {
	if tuple.Protocol != "tcp" && tuple.Protocol != "udp" && tuple.Protocol != "icmp" {
		return false
	}
	if !tuple.ClientIP.IsValid() || !tuple.RemoteIP.IsValid() {
		return false
	}
	if tuple.Protocol == "tcp" || tuple.Protocol == "udp" {
		return tuple.RemotePort != 0
	}
	return true
}

// Key preserves the repository's existing persisted flow-key format exactly.
func (tuple FlowTuple) Key() string {
	if !tuple.Valid() {
		return ""
	}
	return fmt.Sprintf("%s|%s|%d|%s|%d", tuple.Protocol, tuple.ClientIP, tuple.ClientPort, tuple.RemoteIP, tuple.RemotePort)
}
