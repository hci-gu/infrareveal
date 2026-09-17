#!/usr/bin/env bash
# Sourced by entrypoint.sh. Keep policy scoped to InfraReveal-owned chains.
network_defaults() {
  AP_IFACE="${AP_IFACE:-wlan0}"
  ADMIN_IFACE="${ADMIN_IFACE:-wlan1}"
  INTERNET_IFACE="${INTERNET_IFACE:-eth0}"
  AP_PREFIX="${AP_PREFIX:-10.0.0}"
  ADMIN_PREFIX="${ADMIN_PREFIX:-10.77.0}"
  SSID="${SSID:-Infrareveal}"
  ADMIN_SSID="${ADMIN_SSID:-Infrareveal-admin}"
  WIFI_COUNTRY="${WIFI_COUNTRY:-SE}"
  AP_CHANNEL="${AP_CHANNEL:-1}"
  ADMIN_CHANNEL="${ADMIN_CHANNEL:-6}"
  CONFIG_DIR="${CONFIG_DIR:-/run/infrareveal}"
  ADMIN_WIFI_PASSWORD_FILE="${ADMIN_WIFI_PASSWORD_FILE:-/run/secrets/admin_wifi_password}"
  export AP_IFACE ADMIN_IFACE INTERNET_IFACE AP_PREFIX ADMIN_PREFIX
  export SSID ADMIN_SSID WIFI_COUNTRY AP_CHANNEL ADMIN_CHANNEL ADMIN_WIFI_PASSWORD_FILE
  # One source of truth: admin addresses can never enter the observation scope.
  export CLIENT_CIDRS="$AP_PREFIX.0/24" GATEWAY_IP="$AP_PREFIX.1"
  export PACKET_ACTIVITY_IFACE="$AP_IFACE" LAB_GATE_CLIENT_SUBNET="$AP_PREFIX.0/24"
  export DNSMASQ_LOG_PATH=/var/log/dnsmasq.log
}

write_network_configs() {
  install -d -m 700 "$CONFIG_DIR"
  local password
  password=$(cat "$ADMIN_WIFI_PASSWORD_FILE")
  umask 077
  cat > "$CONFIG_DIR/participants.hostapd" <<CONFIG
interface=$AP_IFACE
driver=nl80211
ssid=$SSID
country_code=$WIFI_COUNTRY
hw_mode=g
channel=$AP_CHANNEL
ieee80211n=1
wmm_enabled=1
auth_algs=1
CONFIG
  cat > "$CONFIG_DIR/admin.hostapd" <<CONFIG
interface=$ADMIN_IFACE
driver=nl80211
ssid=$ADMIN_SSID
country_code=$WIFI_COUNTRY
hw_mode=g
channel=$ADMIN_CHANNEL
ieee80211n=1
wmm_enabled=1
auth_algs=1
wpa=2
wpa_key_mgmt=WPA-PSK
rsn_pairwise=CCMP
wpa_passphrase=$password
CONFIG
  unset password
  cat > "$CONFIG_DIR/participants.dnsmasq" <<CONFIG
interface=$AP_IFACE
listen-address=$AP_PREFIX.1
bind-interfaces
except-interface=lo
domain-needed
bogus-priv
dhcp-authoritative
dhcp-range=$AP_PREFIX.50,$AP_PREFIX.150,255.255.255.0,12h
dhcp-option=3,$AP_PREFIX.1
dhcp-option=6,$AP_PREFIX.1
pid-file=$CONFIG_DIR/participants.pid
dhcp-leasefile=$CONFIG_DIR/participants.leases
log-facility=/var/log/dnsmasq.log
log-queries=extra
log-dhcp
CONFIG
  cat > "$CONFIG_DIR/admin.dnsmasq" <<CONFIG
interface=$ADMIN_IFACE
listen-address=$ADMIN_PREFIX.1
bind-interfaces
except-interface=lo
domain-needed
bogus-priv
dhcp-authoritative
dhcp-range=$ADMIN_PREFIX.50,$ADMIN_PREFIX.150,255.255.255.0,12h
dhcp-option=3,$ADMIN_PREFIX.1
dhcp-option=6,$ADMIN_PREFIX.1
pid-file=$CONFIG_DIR/admin.pid
dhcp-leasefile=$CONFIG_DIR/admin.leases
host-record=infrareveal.home.arpa,$ADMIN_PREFIX.1
local=/home.arpa/
# No query logging on the admin resolver.
log-facility=-
CONFIG
  # dnsmasq drops privileges; the directory remains private to root. Keep DHCP
  # lease writes in a separate directory accessible to the dnsmasq user.
  install -d -o dnsmasq -g nogroup -m 750 /var/lib/infrareveal
  sed -i "s|dhcp-leasefile=$CONFIG_DIR/|dhcp-leasefile=/var/lib/infrareveal/|" "$CONFIG_DIR/"*.dnsmasq
}

reset_chain() {
  local tool=$1 table=$2 chain=$3 parent=$4
  "$tool" -w -t "$table" -N "$chain" 2>/dev/null || true
  # Install the jump before populating. Restarting only flushes our own chain.
  "$tool" -w -t "$table" -C "$parent" -j "$chain" 2>/dev/null || \
    "$tool" -w -t "$table" -I "$parent" 1 -j "$chain"
  "$tool" -w -t "$table" -F "$chain"
}

configure_firewall() {
  reset_chain iptables filter IR_INPUT INPUT
  # Binding an address alone does not constrain its ingress interface on Linux.
  iptables -w -A IR_INPUT -i lo -j RETURN
  iptables -w -A IR_INPUT -i "$ADMIN_IFACE" -s "$ADMIN_PREFIX.0/24" -p tcp -m multiport --dports 22,80,8081 -j ACCEPT
  iptables -w -A IR_INPUT -p tcp -m multiport --dports 80,8080,8081,8090 -j REJECT
  local iface prefix
  for iface in "$AP_IFACE" "$ADMIN_IFACE"; do
    iptables -w -A IR_INPUT -i "$iface" -p udp --dport 67 -j ACCEPT
    iptables -w -A IR_INPUT -i "$iface" -p udp --dport 53 -j ACCEPT
    iptables -w -A IR_INPUT -i "$iface" -p tcp --dport 53 -j ACCEPT
    iptables -w -A IR_INPUT -i "$iface" -p icmp -j ACCEPT
    iptables -w -A IR_INPUT -i "$iface" -j REJECT
  done

  reset_chain iptables filter IR_FORWARD FORWARD
  for iface in "$AP_IFACE" "$ADMIN_IFACE"; do
    prefix=$AP_PREFIX
    [ "$iface" != "$ADMIN_IFACE" ] || prefix=$ADMIN_PREFIX
    iptables -w -A IR_FORWARD -i "$iface" -o "$INTERNET_IFACE" -s "$prefix.0/24" -j ACCEPT
    iptables -w -A IR_FORWARD -i "$INTERNET_IFACE" -o "$iface" -d "$prefix.0/24" -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
    iptables -w -A IR_FORWARD -i "$iface" -j REJECT
    iptables -w -A IR_FORWARD -o "$iface" -j REJECT
  done

  reset_chain iptables nat IR_NAT POSTROUTING
  for prefix in "$AP_PREFIX" "$ADMIN_PREFIX"; do
    iptables -w -t nat -A IR_NAT -s "$prefix.0/24" -o "$INTERNET_IFACE" -j MASQUERADE
  done
  reset_chain iptables nat IR_DNS PREROUTING
  local protocol
  for protocol in udp tcp; do
    iptables -w -t nat -A IR_DNS -i "$AP_IFACE" -p "$protocol" --dport 53 -j REDIRECT --to-ports 53
  done
  # This deployment is IPv4-only. Do not permit an IPv6 path around isolation.
  if [ -e /proc/net/if_inet6 ]; then
    reset_chain ip6tables filter IR_INPUT INPUT
    reset_chain ip6tables filter IR_FORWARD FORWARD
    ip6tables -w -A IR_INPUT -i lo -j RETURN
    ip6tables -w -A IR_INPUT -p tcp -m multiport --dports 80,8080,8081,8090 -j REJECT
    for iface in "$AP_IFACE" "$ADMIN_IFACE"; do
      ip6tables -w -A IR_INPUT -i "$iface" -j DROP
      ip6tables -w -A IR_FORWARD -i "$iface" -j DROP
      ip6tables -w -A IR_FORWARD -o "$iface" -j DROP
    done
  fi
}

remove_legacy_rules() {
  # Migrate exact rules emitted by the previous entrypoint; no global flushes.
  local port protocol
  for port in 80 443; do
    while iptables -w -t nat -C PREROUTING -i "$AP_IFACE" -p tcp --dport "$port" -j REDIRECT --to-port 1337 2>/dev/null; do
      iptables -w -t nat -D PREROUTING -i "$AP_IFACE" -p tcp --dport "$port" -j REDIRECT --to-port 1337
    done
  done
  for protocol in udp tcp; do
    while iptables -w -t nat -C PREROUTING -i "$AP_IFACE" -p "$protocol" --dport 53 -j REDIRECT --to-ports 53 2>/dev/null; do
      iptables -w -t nat -D PREROUTING -i "$AP_IFACE" -p "$protocol" --dport 53 -j REDIRECT --to-ports 53
    done
  done
  while iptables -w -t nat -C POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE 2>/dev/null; do
    iptables -w -t nat -D POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE
  done
  while iptables -w -C FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT 2>/dev/null; do
    iptables -w -D FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT
  done
  while iptables -w -C FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null; do
    iptables -w -D FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  done
}
