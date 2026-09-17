#!/usr/bin/env bash
set -euo pipefail

cleanup_lab_rules() {
  while iptables -w -C FORWARD -j INFRAREVEAL_LAB 2>/dev/null; do
    iptables -w -D FORWARD -j INFRAREVEAL_LAB 2>/dev/null || break
  done
  while iptables -w -C INPUT -j INFRAREVEAL_LAB_DNS 2>/dev/null; do
    iptables -w -D INPUT -j INFRAREVEAL_LAB_DNS 2>/dev/null || break
  done
  iptables -w -F INFRAREVEAL_LAB 2>/dev/null || true
  iptables -w -X INFRAREVEAL_LAB 2>/dev/null || true
  iptables -w -F INFRAREVEAL_LAB_DNS 2>/dev/null || true
  iptables -w -X INFRAREVEAL_LAB_DNS 2>/dev/null || true
  ipset flush infrareveal_lab_clients 2>/dev/null || true
  ipset destroy infrareveal_lab_clients 2>/dev/null || true
}

if [ "${INFRAREVEAL_ENTRYPOINT_LIBRARY_ONLY:-false}" = "true" ]; then
  if [ "${BASH_SOURCE[0]}" != "$0" ]; then
    return 0
  fi
  exit 0
fi

# shellcheck source=scripts/gateway-network.sh
source /root/scripts/gateway-network.sh
network_defaults
# Allow USB enumeration after boot. Missing adapters cause an actionable failure.
for ((attempt=0; attempt<30; attempt++)); do
  if ip link show "$AP_IFACE" >/dev/null 2>&1 && ip link show "$ADMIN_IFACE" >/dev/null 2>&1; then
    break
  fi
  sleep 1
done
python3 /root/scripts/gateway-preflight.py
write_network_configs
cleanup_lab_rules
configure_firewall
remove_legacy_rules

# The host must leave both Wi-Fi interfaces unmanaged; Ethernet stays on DHCP.
for iface in "$AP_IFACE" "$ADMIN_IFACE"; do
  ip link set "$iface" up
  ip -4 addr flush dev "$iface"
done
ip addr add "$AP_PREFIX.1/24" dev "$AP_IFACE"
ip addr add "$ADMIN_PREFIX.1/24" dev "$ADMIN_IFACE"
echo 1 > /proc/sys/net/ipv4/ip_forward

children=()
# Called by the EXIT trap.
# shellcheck disable=SC2329
cleanup() {
  trap - EXIT TERM INT
  cleanup_lab_rules
  for child in "${children[@]}"; do kill -TERM "$child" 2>/dev/null || true; done
  for child in "${children[@]}"; do wait "$child" 2>/dev/null || true; done
  # Retain isolation rules if another service is still listening during shutdown.
}
trap cleanup EXIT
trap 'exit 0' TERM INT

hostapd "$CONFIG_DIR/participants.hostapd" "$CONFIG_DIR/admin.hostapd" &
children+=("$!")
dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/participants.dnsmasq" &
children+=("$!")
dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/admin.dnsmasq" &
children+=("$!")
/root/pb/infra-reveal serve --http=127.0.0.1:8090 --dir=/root/pb/pb_data &
children+=("$!")

# Any essential daemon exiting restarts the whole gateway through Compose.
set +e
wait -n "${children[@]}"
status=$?
set -e
echo "A gateway service exited (status $status); restarting the gateway." >&2
exit 1
