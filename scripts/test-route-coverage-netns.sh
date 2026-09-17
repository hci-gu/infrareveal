#!/usr/bin/env bash
set -euo pipefail

# Run in an isolated Linux container with NET_ADMIN/SYS_ADMIN/NET_RAW. It creates
# only private namespaces, never changes the host firewall, and probes no Internet IPs.
if [ "$(uname -s)" != Linux ] || [ "$(id -u)" -ne 0 ]; then
  echo "SKIP: route coverage namespace test requires root on Linux"
  exit 0
fi
for command in ip iptables scamper traceroute tcpdump; do
  command -v "$command" >/dev/null || { echo "missing $command" >&2; exit 1; }
done
ROUTING_TEST_BINARY="${1:?Pass a Linux routing.test binary (go test -c ./routing)}"
SENDER="ir-route-send-$$"
ROUTER="ir-route-hop-$$"
DESTINATION="ir-route-dest-$$"
cleanup() {
  for namespace in "$SENDER" "$ROUTER" "$DESTINATION"; do
    ip netns del "$namespace" 2>/dev/null || true
  done
}
trap cleanup EXIT
for namespace in "$SENDER" "$ROUTER" "$DESTINATION"; do
  ip netns add "$namespace"
  ip -n "$namespace" link set lo up
done
ip -n "$SENDER" link add send type veth peer name upstream
ip -n "$SENDER" link set upstream netns "$ROUTER"
ip -n "$ROUTER" link add downstream type veth peer name dest
ip -n "$ROUTER" link set dest netns "$DESTINATION"
ip -n "$SENDER" addr add 10.249.1.2/24 dev send
ip -n "$ROUTER" addr add 10.249.1.1/24 dev upstream
ip -n "$ROUTER" addr add 10.249.2.1/24 dev downstream
ip -n "$DESTINATION" addr add 10.249.2.2/24 dev dest
ip -n "$SENDER" link set send up
ip -n "$ROUTER" link set upstream up
ip -n "$ROUTER" link set downstream up
ip -n "$DESTINATION" link set dest up
ip -n "$SENDER" route add default via 10.249.1.1
ip -n "$DESTINATION" route add default via 10.249.2.1
ip -n "$SENDER" -6 addr add fd42:249:1::2/64 dev send nodad
ip -n "$ROUTER" -6 addr add fd42:249:1::1/64 dev upstream nodad
ip -n "$ROUTER" -6 addr add fd42:249:2::1/64 dev downstream nodad
ip -n "$DESTINATION" -6 addr add fd42:249:2::2/64 dev dest nodad
ip -n "$SENDER" -6 route add default via fd42:249:1::1
ip -n "$DESTINATION" -6 route add default via fd42:249:2::1
ip netns exec "$ROUTER" sh -c 'echo 1 > /proc/sys/net/ipv6/conf/all/forwarding'
ip netns exec "$ROUTER" sh -c 'echo 1 > /proc/sys/net/ipv4/ip_forward; echo 0 > /proc/sys/net/ipv4/icmp_ratelimit'
ip netns exec "$DESTINATION" sh -c 'echo 0 > /proc/sys/net/ipv4/icmp_ratelimit'

reset_loss() {
  ip netns exec "$ROUTER" iptables -F OUTPUT
  # Drop the first and then every other Time Exceeded reply. A one-query
  # traceroute misses this hop; a retry can recover it.
  ip netns exec "$ROUTER" iptables -A OUTPUT -p icmp --icmp-type time-exceeded -m statistic --mode nth --every 2 --packet 0 -j DROP
}
reset_loss
ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE=legacy "$ROUTING_TEST_BINARY" -test.run '^TestLinuxCoverageNetwork$' -test.v
for method in tcp udp-paris icmp-paris; do
  reset_loss
  ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE="$method" "$ROUTING_TEST_BINARY" -test.run '^TestLinuxCoverageNetwork$' -test.v
done
ip netns exec "$ROUTER" iptables -F OUTPUT
for method in tcp udp-paris icmp-paris; do
  ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE="v6-$method" "$ROUTING_TEST_BINARY" -test.run '^TestLinuxWholeTaskBoundaries$' -test.v
done
ip netns exec "$ROUTER" iptables -t nat -A POSTROUTING -o downstream -j MASQUERADE
ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE=nat "$ROUTING_TEST_BINARY" -test.run '^TestLinuxWholeTaskBoundaries$' -test.v
ip netns exec "$ROUTER" iptables -t nat -F POSTROUTING
ip netns exec "$ROUTER" iptables -A FORWARD -j DROP
ip netns exec "$ROUTER" iptables -A OUTPUT -p icmp -j DROP
ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE=cancel "$ROUTING_TEST_BINARY" -test.run '^TestLinuxWholeTaskBoundaries$' -test.v
ip netns exec "$ROUTER" iptables -F FORWARD
ip netns exec "$ROUTER" iptables -F OUTPUT
ip netns exec "$SENDER" iptables -A INPUT -p icmp --icmp-type time-exceeded -j DROP
ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE=diagnostic "$ROUTING_TEST_BINARY" -test.run '^TestLinuxRouteDiagnostic$' -test.v
ip netns exec "$SENDER" iptables -F INPUT
ip netns exec "$SENDER" env IR_ROUTE_NETNS_CASE=diagnostic-fast "$ROUTING_TEST_BINARY" -test.run '^TestLinuxRouteDiagnostic$' -test.v
echo "Route coverage namespace test passed"
