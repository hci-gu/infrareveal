#!/usr/bin/env bash
# Run inside a disposable privileged Linux container. Uses network namespaces
# and veths, never a real Wi-Fi interface or the host network namespace.
set -euo pipefail
# shellcheck source=scripts/gateway-network.sh
source /root/scripts/gateway-network.sh
network_defaults

# Emulate the two Wi-Fi interfaces with clients in their own namespaces.
for pair in 'wlan0 participant 10.0.0' 'wlan1 admin 10.77.0'; do
  read -r iface ns prefix <<< "$pair"
  ip netns add "$ns"
  ip link add "$iface" type veth peer name client
  ip link set client netns "$ns"
  ip addr add "$prefix.1/24" dev "$iface"
  ip link set "$iface" up
  ip netns exec "$ns" ip link set lo up
  ip netns exec "$ns" ip addr add "$prefix.50/24" dev client
  ip netns exec "$ns" ip link set client up
  ip netns exec "$ns" ip route add default via "$prefix.1"
done
# Emulate an uplink peer without depending on public internet availability.
ip netns add upstream
ip link add upstream-test type veth peer name client
ip link set client netns upstream
# Use a separate routed veth as the test uplink instead of the Docker NIC.
export INTERNET_IFACE=upstream-test
ip addr add 198.18.0.1/24 dev upstream-test
ip link set upstream-test up
ip netns exec upstream ip link set lo up
ip netns exec upstream ip addr add 198.18.0.2/24 dev client
ip netns exec upstream ip link set client up
ip netns exec upstream ip route add 10.77.0.0/24 via 198.18.0.1
ip netns exec upstream ip route add 10.0.0.0/24 via 198.18.0.1
echo 1 > /proc/sys/net/ipv4/ip_forward
configure_firewall
# Must be safe to reapply without duplicate jumps or losing isolation.
configure_firewall
[ "$(iptables -S INPUT | grep -c -- '-j IR_INPUT')" -eq 1 ]

python3 -m http.server 80 --bind 0.0.0.0 >/tmp/http.log 2>&1 &
server_pid=$!
ip netns exec upstream python3 -m http.server 8000 --bind 0.0.0.0 >/tmp/upstream.log 2>&1 &
upstream_pid=$!
trap 'kill "$server_pid" "$upstream_pid" 2>/dev/null || true' EXIT
sleep 1
ip netns exec admin curl -fsS --max-time 3 http://10.77.0.1/ >/dev/null
for attempt in 'participant 10.0.0.1' 'participant 10.77.0.1' 'upstream 10.77.0.1'; do
  read -r ns address <<< "$attempt"
  if ip netns exec "$ns" curl -fsS --max-time 2 "http://$address/" >/dev/null 2>&1; then
    echo "Management isolation failed: $attempt" >&2
    exit 1
  fi
done
# Both networks retain internet forwarding; cross-network forwarding is blocked.
for ns in participant admin; do
  ip netns exec "$ns" curl -fsS --max-time 3 http://198.18.0.2:8000/ >/dev/null
done
ip netns exec participant python3 -m http.server 8001 >/tmp/participant.log 2>&1 &
participant_pid=$!
sleep 1
if ip netns exec admin curl -fsS --max-time 2 http://10.0.0.50:8001/ >/dev/null 2>&1; then
  echo 'Admin-to-participant isolation failed' >&2
  exit 1
fi
kill "$participant_pid"

# Validate generated configs, admin secrecy, and two independent resolvers.
ADMIN_WIFI_PASSWORD_FILE=/tmp/test-admin-password
printf '%s\n' 'only-a-test-password' > "$ADMIN_WIFI_PASSWORD_FILE"
write_network_configs
dnsmasq --test --conf-file="$CONFIG_DIR/participants.dnsmasq"
dnsmasq --test --conf-file="$CONFIG_DIR/admin.dnsmasq"
if grep -q '^log-queries' "$CONFIG_DIR/admin.dnsmasq"; then exit 1; fi
grep -q '^log-queries=extra' "$CONFIG_DIR/participants.dnsmasq"
[ "$(stat -c %a "$CONFIG_DIR/admin.hostapd")" = 600 ]
dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/participants.dnsmasq" >/tmp/dns-participant.log 2>&1 &
dns_participant=$!
dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/admin.dnsmasq" >/tmp/dns-admin.log 2>&1 &
dns_admin=$!
sleep 1
kill -0 "$dns_participant" "$dns_admin"
# Query the admin DNS using a raw DNS packet; no extra test dependencies.
ip netns exec admin python3 - <<'PY'
import socket
query = bytes.fromhex('123401000001000000000000')
for label in 'infrareveal.home.arpa'.split('.'):
    query += bytes([len(label)]) + label.encode()
query += b'\x00\x00\x01\x00\x01'
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(3)
s.sendto(query, ('10.77.0.1', 53))
response, _ = s.recvfrom(4096)
assert response[-4:] == socket.inet_aton('10.77.0.1'), response
PY
if grep -q infrareveal.home.arpa /var/log/dnsmasq.log; then exit 1; fi
kill "$dns_participant" "$dns_admin"
echo 'PASS: management isolation, subnet separation, NAT, repeatable rules, DNS configs and local admin DNS'
