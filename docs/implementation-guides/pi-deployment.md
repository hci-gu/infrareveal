# Deploy the two-network Raspberry Pi gateway

The Pi runs the UI, PocketBase, two access points, DHCP/DNS and NAT. Ethernet
obtains an uplink address from the host OS. No upstream port forwarding or fixed
Ethernet address is needed.

| Connection | Purpose | Default |
| --- | --- | --- |
| `eth0` | Ethernet internet uplink | Host DHCP |
| `wlan0` / `Infrareveal` | Existing open observation network | `10.0.0.1/24` |
| `wlan1` / `Infrareveal-admin` | WPA2-protected operator network | `10.77.0.1/24` |
| Admin dashboard | Main UI and same-origin API | `http://10.77.0.1/` |
| Admin hostname | Resolved by the Pi's admin DNS | `http://infrareveal.home.arpa/` |
| PocketBase console | Via dashboard reverse proxy | `http://10.77.0.1/_/` |
| Debug dashboard | Enable the `debug` Compose profile | `http://10.77.0.1:8081/` |

Both wireless networks have internet through Ethernet. Forwarding between them
is blocked. Only participant traffic is captured; separate DNS services and a
backend client-subnet filter exclude admin DNS too. PocketBase listens on
`127.0.0.1:8090`. The web servers bind the admin address, and ingress firewall
rules reject web management access from Ethernet and participant Wi-Fi. SSH
remains available over Ethernet and is allowed from admin Wi-Fi.

The UI and API remain accessible without an internet uplink, but the current
basemap tiles/fonts require internet. This is an IPv4 deployment; IPv6 forwarding
and access from both Wi-Fi interfaces are blocked to prevent an isolation bypass.

## Existing Pi: verified inventory

Checked on 2026-09-17:

- SSH: `pi@192.168.10.120` (this Ethernet DHCP address can change).
- Raspberry Pi 4 Model B, Raspberry Pi OS Bullseye **32-bit**, Docker 20.10.12.
- Built-in `brcmfmac` radio: `wlan0`, already broadcasting `Infrareveal`.
- Ralink RT5370 USB adapter: `wlan1`, driver `rt2800usb`, AP support advertised.
- Repository: `/home/pi/Documents/infrareveal`.
- Old container: `infrareveal-server`.
- Existing database: `/home/pi/Documents/infrareveal/data`, mounted at
  `/root/pb/pb_data`. The new deployment uses that same directory explicitly.
- Host networking uses `dhcpcd`. Compose is not installed.

The Dockerfiles select the target Go architecture automatically, and use Node 22
for frontend builds because its official image includes ARMv7. ARMv7 runtime
images can also be cross-built on a Mac or 64-bit Linux machine. A 64-bit OS is
recommended for future installations, but reinstalling this Pi is not required.
Docker Engine 28 is the last major release for Raspberry Pi OS 32-bit; don't
blindly upgrade this host to Engine 29+. See the [Docker support notes](https://docs.docker.com/engine/install/raspberry-pi-os/).

## 1. Pull the source and install Compose

These instructions assume the changes have first been committed and pushed to
the branch used by the Pi. Run over **Ethernet SSH**, not participant Wi-Fi.

```bash
ssh pi@192.168.10.120
cd /home/pi/Documents/infrareveal
git status --short
git pull --ff-only
```

If tracked local edits prevent the pull, preserve/reconcile them first. Do not
reset the checkout or delete the existing `data` directory.

For this Pi's older Docker engine, install the pinned ARMv7 Compose plugin below.
The pin keeps deployment tooling reproducible; it is not a claim that this is the
latest Compose release. A fresh 64-bit installation can instead use Docker's
normal `docker-compose-plugin` and `docker-buildx-plugin` packages.

```bash
mkdir -p /tmp/infrareveal-compose
cd /tmp/infrareveal-compose
curl -fLO https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-armv7
curl -fLO https://github.com/docker/compose/releases/download/v2.39.4/docker-compose-linux-armv7.sha256
sha256sum -c docker-compose-linux-armv7.sha256
sudo mkdir -p /usr/local/lib/docker/cli-plugins
sudo install -m 755 docker-compose-linux-armv7 /usr/local/lib/docker/cli-plugins/docker-compose
sudo docker compose version
cd /home/pi/Documents/infrareveal
```

This follows Docker's [manual plugin installation](https://docs.docker.com/compose/install/linux/).
The plugin is system-wide so `sudo docker compose` can find it.

## 2. Configure networking and preserve GeoIP assets

```bash
cp -n .env.example .env
mkdir -p data geoip
nano .env
```

The `Infrareveal-admin` Wi-Fi password is always **`password123`**. No password
file or Compose secret is needed. Existing `secrets/admin-wifi-password` files
are ignored after upgrading. This is the Wi-Fi password; your PocketBase
superuser login remains the one you created. `.env`, `data` and `geoip` are
excluded from Git and the Docker build context.

In `.env`, retain `wlan0` / `wlan1` and country `SE` for this Pi. Optionally set
`ADMIN_WIFI_MAC=38:a2:8c:a2:1f:c9` to verify that `wlan1` is the inspected adapter.
Uncomment `COMPOSE_PROFILES=debug` to deploy the debug dashboard too.

The new images load GeoIP databases from `./geoip` at runtime. Copy the existing
city database out of the old container **before removing it**:

```bash
sudo docker cp infrareveal-server:/root/geoip/city.mmdb ./geoip/city.mmdb
```

If you already have `geoip/city.mmdb`, keep that version or back it up before
replacing it. An optional ASN database belongs at `geoip/asn.mmdb`. Fresh installs
can use their own licensed GeoIP files; the gateway runs without them, with
reduced location/provider information. Database files are not bundled in Git.

## 3. Build before interrupting the current gateway

```bash
sudo bash scripts/build-pi-images.sh
sudo docker compose config --quiet
```

This builds all three images natively, including ARMv7 on the existing Pi, using
Docker Engine's built-in BuildKit. It does not require the Buildx plugin. Builds
on the Pi may take several minutes and require free disk space. The previous
container continues running while images build. On modern Docker installations,
`sudo docker compose --profile debug build` is also supported.

## 4. Let the containers own both Wi-Fi interfaces

On this Pi's **dhcpcd-based Bullseye** installation:

```bash
sudo cp -n /etc/dhcpcd.conf /etc/dhcpcd.conf.before-infrareveal-admin
sudo sh -c 'grep -qxF "denyinterfaces wlan0 wlan1" /etc/dhcpcd.conf || printf "\ndenyinterfaces wlan0 wlan1\n" >> /etc/dhcpcd.conf'
sudo systemctl disable --now wpa_supplicant.service
sudo systemctl disable --now wpa_supplicant@wlan0.service wpa_supplicant@wlan1.service
sudo systemctl restart dhcpcd
```

An absent per-interface service may report "not loaded"; that is fine. Ethernet
stays managed by dhcpcd. Restarting it can briefly interrupt SSH; reconnect if
needed. Do not enable a host hostapd/dnsmasq service alongside the containers.
This dedicates both Wi-Fi radios to InfraReveal.

On a **fresh NetworkManager-based OS**, instead configure both radios unmanaged
in `/etc/NetworkManager/conf.d/90-infrareveal.conf`:

```ini
[keyfile]
unmanaged-devices=interface-name:wlan0;interface-name:wlan1
```

Then reload NetworkManager and release the interfaces with
`sudo nmcli general reload`, `sudo nmcli device set wlan0 managed no`, and
`sudo nmcli device set wlan1 managed no`. Keep Ethernet on automatic DHCP. Do not
apply both networking-manager recipes indiscriminately.

The inspected Pi also had an extra `192.168.1.100/24` address on Ethernet. Its
source was not in dhcpcd.conf. Inspect `ip -4 address show eth0` and any custom
startup scripts; remove that obsolete static configuration when identified.
Do not remove the active DHCP address or default route.

## 5. Stop the old container, back up, and start Compose

This step interrupts participant Wi-Fi. Stop the old gateway before starting
the new one, because both own the same interfaces, firewall and database.

```bash
cd /home/pi/Documents/infrareveal
sudo docker update --restart=no infrareveal-server
sudo docker stop infrareveal-server
backup_dir="../infrareveal-data-backup-$(date +%Y%m%d-%H%M%S)"
sudo cp -a data "$backup_dir"
sudo docker compose up -d --no-build
sudo docker compose ps
sudo docker compose logs --tail=100 proxy dashboard
```

Keep the stopped old container and the backup until the new setup is verified.
The gateway explicitly uses `/root/pb/pb_data`, preserving the existing bind
mount. Do not run both old and new binaries against that directory concurrently.
Migrations may change the database; rollback should use the stopped-state backup.

## 6. Verify from the two networks

1. Join `Infrareveal-admin` using `password123`. Expect a
   `10.77.0.50–150` address.
2. Open **http://10.77.0.1/**. The DNS name
   **http://infrareveal.home.arpa/** should work when using the Wi-Fi's DNS.
   Devices using private/encrypted DNS can use the IP address instead.
3. Check **http://10.77.0.1/api/health** and **http://10.77.0.1/_/**.
   If enabled, open **http://10.77.0.1:8081/** for the debug dashboard.
4. Join `Infrareveal` on a separate device. Expect a `10.0.0.50–150` address,
   working internet, and participant observations appearing in the dashboard.
5. Browse from the admin device and confirm its `10.77.0.x` address does not
   appear as an observed client or DNS source. Participant devices must not be
   able to open either dashboard or access admin clients.
6. Confirm dashboard/API access from Ethernet is rejected. SSH still works.
7. Reboot the Pi and repeat the checks. Then test moving Ethernet to another
   ordinary DHCP network. A missing uplink should not prevent local admin access.

The debug profile does not automatically enable Proxy Lab tracing or gates.
Keep the gate disabled unless intentionally running that experiment; its token
mount and allowed origins are described in the [Proxy Lab guide](proxy-lab.md).
When enabled, use the actual admin origin, e.g. `http://10.77.0.1:8081`, in the
allowed-origin configuration.

## Subsequent updates

Once the first migration is complete:

```bash
cd /home/pi/Documents/infrareveal
git pull --ff-only
sudo bash scripts/build-pi-images.sh
sudo docker compose stop
backup_dir="../infrareveal-data-backup-$(date +%Y%m%d-%H%M%S)"
sudo cp -a data "$backup_dir"
sudo docker compose up -d --no-build
sudo docker compose ps
```

Keep `.env`, `data`, and `geoip` between updates. `restart: always` starts the
services again after reboot. The gateway waits up to 30 seconds for both radios,
validates configuration, and exits with a readable error if either is absent.

## Portability and troubleshooting

- **Overlapping uplink:** preflight refuses to modify interfaces if a non-default
  local route overlaps either Wi-Fi subnet. Choose unused private prefixes in
  `.env` (`AP_PREFIX`, `ADMIN_PREFIX`), then recreate **all** services with
  `sudo docker compose up -d --no-build --force-recreate`. DHCP, DNS, observation
  scope and the web listener derive from those prefixes. Rejoin Wi-Fi to renew
  client leases. The printed defaults in these instructions then change too.
- **Managed Ethernet:** a port requiring 802.1X, a captive portal, a static
  address, device registration, or VLAN setup still needs that host configuration.
  This deployment cannot bypass upstream access requirements.
- **Adapter not found / wrong MAC:** inspect `/usr/sbin/iw dev`, `lsusb`, and
  `ip -brief link`; fix `.env` rather than assigning the roles to an arbitrary
  interface. The preflight and hostapd errors appear in `docker compose logs proxy`.
- **Host networking conflicts:** verify dhcpcd/NetworkManager/wpa_supplicant no
  longer manage the radios. The gateway deliberately does not kill host processes.
- **UI unavailable:** `sudo docker compose ps` should show a healthy proxy and
  running dashboard. Check the admin lease/address and logs. PocketBase's direct
  port `8090` is intentionally inaccessible from other machines.
- **No internet:** inspect the host's `ip route` and DNS configuration. dnsmasq
  uses the container's resolver configuration inherited from the host; recreate
  the proxy if an uplink change leaves stale DNS servers.
- **Firewall ownership:** only `IR_*` and the existing lab chains are managed.
  Isolation rules remain on shutdown so a still-running web service is protected.
  A host reboot clears non-persisted rules. Existing external firewall policy can
  still interfere; do not globally flush the Pi's firewall to troubleshoot.

## Development verification

```bash
bash scripts/test-entrypoint.sh
python3 scripts/test-gateway-preflight.py
(cd pocketbase && go test ./observer)
docker build -t infrareveal-gateway:network-test .
docker run --rm --privileged --entrypoint bash \
  -v "$PWD/scripts/test-gateway-network.sh:/test.sh:ro" \
  infrareveal-gateway:network-test /test.sh
```

The network test uses veth clients in disposable network namespaces. Never add
`--network host` to it. It verifies management isolation, cross-subnet blocking,
both uplink NAT paths, repeatable rules, separate DNS services and the local admin
hostname. Run it in a **native-architecture** Linux container: emulated ARMv7
netlink/iptables calls are not a reliable network-policy test on an ARM64 host.
Radio association, client DHCP and cold-boot behavior require the physical Pi
acceptance checks above.

Validation on 2026-09-17: all three ARMv7 images built; the ARMv7 backend started
and served both dashboards through their same-origin proxies, including immediate
SSE delivery. Observer tests, preflight tests and the native-container network
isolation/DNS test passed. The changes have not yet been applied to the physical
Pi; association, DHCP leases and reboot behavior remain deployment acceptance
checks.

## Always-on lab demo

For the unattended lab display, use the [lab demo guide](lab-demo.md). Set
`DEMO_MODE=true`, `DEMO_RETENTION_MINUTES=30`, and `DEMO_DOMAIN_CATALOGUE=true`
in `.env`, rebuild/recreate the containers, and open `http://10.77.0.1/demo`.
This creates a dedicated rolling session, resumes it after restarts, renews route
budgets, and retains a separate domain-review catalogue.

## Always-on ephemeral sessions

After rebuilding and recreating the containers, migrations add an `ephemeral`
checkbox to the `sessions` collection in PocketBase. Open
**http://10.77.0.1/_/**, sign in, edit the current active session, enable
**ephemeral**, and save. Both dashboards pick up the change automatically.
The same session stays active across restarts; its timeline grows to five
minutes and then slides forward (or use the session’s `retention_minutes`
setting for a different duration). A paused playhead is clamped when it expires.

Enabling this option on an existing session discards history older than five
minutes. Disable it to keep new history from the remaining window; also clear
`active` if you want to stop the session. Ordinary sessions are unaffected.

Every 15 seconds the backend removes expired observations and packet chunks.
Connections still seen in the window retain their identity and necessary DNS
and route evidence, even when they were opened hours ago. Traffic columns use
only retained packet chunks, with partial boundary chunks marked as partial.
Browser records, timeline indexes, colors, queued events and detail pages are
also evicted; requests are cancelled on teardown and time out on lost networks.

Storage depends on traffic volume and concurrent connections, rather than how
many days this session has run. SQLite reuses deleted pages, so an existing large
database may keep its previous file size. Other recorded sessions still take up
space. Docker logs rotate at 10 MiB with three files per service, and the DNS
capture spool is truncated after it exceeds 8 MiB and the reader has caught up.

To apply these changes on the Pi, use the normal update commands above, including
`sudo bash scripts/build-pi-images.sh` and
`sudo docker compose up -d --no-build --force-recreate`.
Reconnect to admin Wi-Fi with `password123` after the gateway restarts.
