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

children=()
# Install shutdown handling before waiting for a possibly unplugged USB radio.
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

# Wait indefinitely without a restart loop. Background + wait keeps PID 1
# responsive to Docker stop while the USB adapter is absent.
python3 /root/scripts/gateway-runtime.py wait &
children+=("$!")
wait "${children[0]}"
children=()
python3 /root/scripts/gateway-preflight.py
write_network_configs
cleanup_lab_rules
configure_firewall
remove_legacy_rules

# The host must leave enabled Wi-Fi interfaces unmanaged; Ethernet stays on DHCP.
for i in "${!WIFI_IFACES[@]}"; do
  iface=${WIFI_IFACES[$i]}
  ip link set "$iface" up
  ip -4 addr flush dev "$iface"
  ip addr add "${WIFI_PREFIXES[$i]}.1/24" dev "$iface"
done
echo 1 > /proc/sys/net/ipv4/ip_forward

# Capture interface identities before starting daemons. The watcher exits even
# when hostapd/dnsmasq stay alive after their USB radio disappears.
python3 /root/scripts/gateway-runtime.py watch &
children+=("$!")

hostapd_configs=("$CONFIG_DIR/participants.hostapd")
if [ "$ADMIN_WIFI_ENABLED" = true ]; then
  hostapd_configs+=("$CONFIG_DIR/admin.hostapd")
fi
hostapd "${hostapd_configs[@]}" &
children+=("$!")
dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/participants.dnsmasq" &
children+=("$!")
if [ "$ADMIN_WIFI_ENABLED" = true ]; then
  dnsmasq --keep-in-foreground --conf-file="$CONFIG_DIR/admin.dnsmasq" &
  children+=("$!")
fi
/root/pb/infra-reveal serve --http=0.0.0.0:8090 --dir=/root/pb/pb_data &
children+=("$!")

# Any essential daemon or the network watcher exiting triggers Compose recovery.
set +e
wait -n "${children[@]}"
status=$?
set -e
echo "A gateway service exited (status $status); restarting the gateway." >&2
exit 1
