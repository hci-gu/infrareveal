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

  kill $MITMDUMP_PID
  kill -TERM "$CHILD" 2> /dev/null

  echo "received shutdown signal, exiting."
}

# Spoof MAC address
if [ "$MAC" != "unchanged" ]; then
  ifconfig "$AP_IFACE" down
  if [ "$MAC" == "random" ]; then
    echo "using random MAC address"
    macchanger -A "$AP_IFACE"
  else
    echo "setting MAC address to $MAC"
    macchanger --mac "$MAC" "$AP_IFACE"
  fi
  if [ $? -ne 0 ]; then
    echo "Failed to change MAC address, aborting."
    exit 1
  fi
  ifconfig "$AP_IFACE" up
fi

ifconfig "$AP_IFACE" 10.0.0.1/24 || {
  echo "Failed to configure $AP_IFACE with IP 10.0.0.1/24"
  exit 1
}

# Configure WPA password if provided
if [ ! -z "$PASSWORD" ]; then
  if [ ${#PASSWORD} -lt 8 ] || [ ${#PASSWORD} -gt 63 ]; then
    echo "PASSWORD must be between 8 and 63 characters"
    echo "password '$PASSWORD' has length: ${#PASSWORD}, exiting."
    exit 1
  fi

  sed -i 's/#//' /etc/hostapd/hostapd.conf
  sed -i "s/wpa_passphrase=.*/wpa_passphrase=$PASSWORD/g" /etc/hostapd/hostapd.conf
fi

sed -i "s/^ssid=.*/ssid=$SSID/g" /etc/hostapd/hostapd.conf
sed -i "s/interface=.*/interface=$AP_IFACE/g" /etc/hostapd/hostapd.conf
sed -i "s/interface=.*/interface=$AP_IFACE/g" /etc/dnsmasq.conf

/etc/init.d/dbus status || /etc/init.d/dbus start
/etc/init.d/dnsmasq status || /etc/init.d/dnsmasq start
/etc/init.d/hostapd status || /etc/init.d/hostapd start

echo 1 > /proc/sys/net/ipv4/ip_forward

# Set up iptables rules
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

# Keep container running
tail -f /dev/null &
CHILD=$!
wait "$CHILD"
