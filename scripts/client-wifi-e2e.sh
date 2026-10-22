#!/usr/bin/env bash
# Run a real browser through one idle physical Wi-Fi radio, then restore it.
set -euo pipefail
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
[[ $EUID == 0 ]] || { echo 'Run with sudo.' >&2; exit 1; }
root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
output=$(realpath -m "${1:?Usage: client-wifi-e2e.sh OUTPUT [browser arguments]}")
shift
iface=${E2E_IFACE:-wlan0}
user=${SUDO_USER:-pi}
namespace="ir-e2e-$$"
[[ $user != root ]] || { echo 'Set SUDO_USER to the browser user.' >&2; exit 1; }
[[ -d /sys/class/net/$iface/phy80211 ]] || { echo 'Select a physical Wi-Fi interface.' >&2; exit 1; }
[[ ! -e $output ]] || { echo 'Use a new output directory for each run.' >&2; exit 1; }
was_up=$(ip -j address show dev "$iface" | python3 -c 'import json,sys; i=json.load(sys.stdin)[0]; assert not i["addr_info"], "Radio must be unaddressed"; print("up" if "UP" in i["flags"] else "down")')
[[ $(iw dev "$iface" link) == 'Not connected.' ]] || { echo 'Radio is already connected.' >&2; exit 1; }
was_ipv6=$(cat "/proc/sys/net/ipv6/conf/$iface/disable_ipv6")
phy=$(basename "$(readlink -f "/sys/class/net/$iface/phy80211")")
mkdir -p "$output" "/etc/netns/$namespace"
chown "$user:" "$output"
cleanup() {
  status=$?
  trap - EXIT INT TERM HUP
  pids=$(ip netns pids "$namespace" 2>/dev/null || true)
  if [[ -n $pids ]]; then
    kill $pids 2>/dev/null || true
    sleep 1
    pids=$(ip netns pids "$namespace" 2>/dev/null || true)
    [[ -z $pids ]] || kill -KILL $pids 2>/dev/null || true
  fi
  ip netns exec "$namespace" iw phy "$phy" set netns 1 2>/dev/null || true
  ip link set "$iface" down 2>/dev/null || true
  ip -4 addr flush dev "$iface" 2>/dev/null || true
  sysctl -q -w "net.ipv6.conf.$iface.disable_ipv6=$was_ipv6" 2>/dev/null || true
  ip link set "$iface" "$was_up" 2>/dev/null || true
  ip netns del "$namespace" 2>/dev/null || true
  rm -f "/etc/netns/$namespace/resolv.conf"
  rmdir "/etc/netns/$namespace" 2>/dev/null || true
  chown -R "$user:" "$output"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
printf 'nameserver 10.0.0.1\n' > "/etc/netns/$namespace/resolv.conf"
cat > "$output/wpa.conf" <<EOF
ctrl_interface=$output/wpa
country=SE
network={
  ssid="Infrareveal"
  key_mgmt=NONE
}
EOF
cat > "$output/dhcp-hook" <<'SH'
#!/bin/sh
case "$reason" in
  BOUND|RENEW|REBIND|REBOOT)
    prefix=$(python3 -c 'import ipaddress,sys; print(ipaddress.IPv4Network("0.0.0.0/"+sys.argv[1]).prefixlen)' "$new_subnet_mask")
    ip -4 addr replace "$new_ip_address/$prefix" dev "$interface"
    set -- $new_routers
    ip route replace default via "$1" dev "$interface"
    : > /etc/resolv.conf
    for server in $new_domain_name_servers; do printf 'nameserver %s\n' "$server" >> /etc/resolv.conf; done
    ;;
esac
SH
chmod 755 "$output/dhcp-hook"
ip netns add "$namespace"
iw phy "$phy" set netns name "$namespace"
ip -n "$namespace" link set lo up
ip netns exec "$namespace" sysctl -q -w net.ipv6.conf.all.disable_ipv6=1
ip -n "$namespace" link set "$iface" up
ip netns exec "$namespace" wpa_supplicant -B -D nl80211 -i "$iface" -c "$output/wpa.conf" -P "$output/wpa.pid" -f "$output/wpa.log"
connected=false
for ((attempt=0; attempt<30; attempt++)); do
  if ip netns exec "$namespace" iw dev "$iface" link | grep -q 'SSID: Infrareveal'; then connected=true; break; fi
  sleep 1
done
$connected || { echo 'Wi-Fi association failed; see wpa.log.' >&2; exit 1; }
ip netns exec "$namespace" timeout 40 dhclient -4 -1 -v -pf "$output/dhcp.pid" -lf "$output/dhcp.leases" -sf "$output/dhcp-hook" "$iface" > "$output/dhcp.log" 2>&1
ip netns exec "$namespace" python3 - "$iface" "$output/network.json" <<'PY'
import json,socket,subprocess,sys
from pathlib import Path
iface,path=sys.argv[1:]
def command(*args): return subprocess.check_output(args,text=True).strip()
links=json.loads(command('ip','-j','address'))
assert {i['ifname'] for i in links}=={'lo',iface}, 'Browser namespace has an extra interface'
route=json.loads(command('ip','-j','route','get','1.1.1.1'))[0]
assert route['dev']==iface and route.get('gateway')=='10.0.0.1',route
assert route['prefsrc'].startswith('10.0.0.'),route
dns=Path('/etc/resolv.conf').read_text()
assert 'nameserver 10.0.0.1' in dns,dns
blocked=[]
for host,port in [('10.0.0.1',8090),('10.77.0.1',80),('10.77.0.1',8081)]:
 try:
  with socket.create_connection((host,port),timeout=2): pass
 except OSError: blocked.append(f'{host}:{port}')
 else: raise AssertionError(f'Participant can access management at {host}:{port}')
Path(path).write_text(json.dumps({'interface':iface,'client_ip':route['prefsrc'],'route':route,'links':links,'dns':dns,'blocked_management':blocked,'association':command('iw','dev',iface,'link')},indent=2)+'\n')
print('Browser route:',route['prefsrc'],'via',route['gateway'],'on',iface,flush=True)
PY
chown -R "$user:" "$output"
ip netns exec "$namespace" runuser -u "$user" -- python3 "$root/client-browsing.py" --output "$output" "$@"
