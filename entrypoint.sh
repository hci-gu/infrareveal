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

# Remove any existing IPs and assign static IP
# Set a static MAC address for wlan0
ip link set "$AP_IFACE" down
ip link set "$AP_IFACE" address 02:00:00:00:01:00
ip link set "$AP_IFACE" up

# Remove old IPs and configure the interface
ip addr flush dev "$AP_IFACE"
ip addr add 10.0.0.1/24 dev "$AP_IFACE" || {
  echo "Failed to assign IP 10.0.0.1 to $AP_IFACE"
  exit 1
}
ip link set "$AP_IFACE" up || {
  echo "Failed to bring up $AP_IFACE"
  exit 1
}

# Stop conflicting services that may use port 53
# if netstat -tuln | grep -q ":53"; then
#   echo "Port 53 is already in use, killing the process..."
#   PID=$(netstat -tuln | grep ":53" | awk '{print $7}' | cut -d/ -f1)
#   if [ -n "$PID" ]; then
#     kill -9 "$PID" || {
#       echo "Failed to kill process on port 53"
#       exit 1
#     }
#   else
#     echo "Could not determine the process using port 53"
#     exit 1
#   fi
# fi

# Update dnsmasq and hostapd configurations
sed -i "s/^ssid=.*/ssid=$SSID/g" /etc/hostapd/hostapd.conf
sed -i "s/interface=.*/interface=$AP_IFACE/g" /etc/hostapd/hostapd.conf
sed -i "s/interface=.*/interface=$AP_IFACE/g" /etc/dnsmasq.conf

# Start services
/etc/init.d/dbus status || /etc/init.d/dbus start
/etc/init.d/dnsmasq start || {
  echo "dnsmasq failed to start"
  exit 1
}
/etc/init.d/hostapd start || {
  echo "hostapd failed to start"
  exit 1
}

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
