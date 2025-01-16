#!/bin/bash

AP_IFACE="${AP_IFACE:-wlan0}"
INTERNET_IFACE="${INTERNET_IFACE:-eth0}"
SSID="${SSID:-Public}"
CAPTURE_FILE="${CAPTURE_FILE:-/root/data/http-traffic.cap}"
MAC="${MAC:-random}"

# SIGTERM-handler
term_handler() {
  iptables -t nat -D POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE
  iptables -D FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT
  iptables -D FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT

  /etc/init.d/dnsmasq stop
  /etc/init.d/hostapd stop
  /etc/init.d/dbus stop

  kill -TERM "$CHILD" 2>/dev/null

  echo "received shutdown signal, exiting."
}

# Set AP interface
ip link set "$AP_IFACE" down
ip link set "$AP_IFACE" address 02:00:00:00:01:00
ip link set "$AP_IFACE" up

# Assign static IP and flush existing IPs
if ! ip addr add 10.0.0.1/24 dev "$AP_IFACE"; then
  echo "Failed to assign IP 10.0.0.1 to $AP_IFACE"
  exit 1
fi

# Verify interface state
if ! ip link set "$AP_IFACE" up; then
  echo "Failed to bring up $AP_IFACE"
  exit 1
fi

# Ensure no lingering processes
pkill -f dnsmasq
pkill -f hostapd

# Update configurations
sed -i "s/^ssid=.*/ssid=$SSID/g" /etc/hostapd/hostapd.conf
sed -i "s/^interface=.*/interface=$AP_IFACE/g" /etc/hostapd/hostapd.conf
sed -i "s/^interface=.*/interface=$AP_IFACE/g" /etc/dnsmasq.conf

# Start dbus if not running
if ! /etc/init.d/dbus status > /dev/null 2>&1; then
  /etc/init.d/dbus start || {
    echo "Failed to start dbus"
    exit 1
  }
fi

# Start dnsmasq
if ! /etc/init.d/dnsmasq start; then
  echo "dnsmasq failed to start"
  ip addr show dev "$AP_IFACE"  # Debug interface state
  exit 1
fi

# Start hostapd
if ! /etc/init.d/hostapd start; then
  echo "hostapd failed to start"
  exit 1
fi

# Enable IP forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward

# Configure iptables rules for NAT and traffic forwarding
iptables -t nat -C POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE 2>/dev/null || \
iptables -t nat -A POSTROUTING -o "$INTERNET_IFACE" -j MASQUERADE

iptables -C FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$INTERNET_IFACE" -o "$AP_IFACE" -m state --state RELATED,ESTABLISHED -j ACCEPT

iptables -C FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT 2>/dev/null || \
iptables -A FORWARD -i "$AP_IFACE" -o "$INTERNET_IFACE" -j ACCEPT

iptables -t nat -C PREROUTING -i "$AP_IFACE" -p tcp --dport 80 -j REDIRECT --to-port 1337 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 80 -j REDIRECT --to-port 1337

iptables -t nat -C PREROUTING -i "$AP_IFACE" -p tcp --dport 443 -j REDIRECT --to-port 1337 2>/dev/null || \
iptables -t nat -A PREROUTING -i "$AP_IFACE" -p tcp --dport 443 -j REDIRECT --to-port 1337

# Signal handling
trap term_handler SIGTERM

# Start infra-reveal
if [ -x /root/pb/infra-reveal ]; then
  /root/pb/infra-reveal serve --http="0.0.0.0:8090" || {
    echo "infra-reveal failed to start"
    exit 1
  }
else
  echo "infra-reveal binary not found or not executable"
  exit 1
fi

# Keep the container running
tail -f /dev/null &
CHILD=$!
wait "$CHILD"
