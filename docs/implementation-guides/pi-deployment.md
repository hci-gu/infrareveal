# Deploy the Raspberry Pi gateway

The default two-radio configuration runs the UI, PocketBase, two access points,
DHCP/DNS and NAT. The existing Pi uses the single-radio proxy-only configuration
described below. Ethernet
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

## Single-radio proxy-only deployment

Use `compose.proxy-only.yml` to run the participant AP on the built-in radio
without the USB admin adapter or dashboard containers. It sets
`ADMIN_WIFI_ENABLED=false`: startup, preflight, watchdog and health checks only
require the participant radio. No admin hostapd/DNS configuration, IP address,
firewall exception or NAT rule is installed. Plugging in another radio does not
enable admin Wi-Fi. Ethernet remains the internet uplink and SSH management path;
the backend API remains on `127.0.0.1:8090`.

For a source checkout, set these values in `.env` (use the actual built-in
interface name, `ir-ap` on the existing Pi):

```dotenv
AP_IFACE=ir-ap
ADMIN_WIFI_ENABLED=false
COMPOSE_FILE=docker-compose.yml:compose.proxy-only.yml
COMPOSE_PROFILES=
```

If the deployment has `compose.release.yml`, place it between the two files in
`COMPOSE_FILE`. Build the gateway image before switching, keeping its existing
data and GeoIP mounts. Stop and remove existing dashboard containers once;
otherwise their previous restart policies can bring them back after reboot.
Then run `docker compose up -d --no-build proxy`. With this configuration, plain
`docker compose up -d` also selects only the proxy. The dashboard profiles are
available only through an explicit override.

Manage the Pi over `ssh pi@192.168.10.120`. To access the backend locally, use
`ssh -L 8090:127.0.0.1:8090 pi@192.168.10.120` and open
`http://127.0.0.1:8090/_/`. The participant network still blocks management ports.
The API, DHCP/DNS, capture and internet forwarding all remain part of the proxy.

## Existing Pi: current deployment and history

**22 October update:** the Pi now runs only the proxy from
`/home/pi/Documents/infrareveal-releases/fb86b7c-single-radio-20261022`, using
`docker-compose.yml`, `compose.release.yml` and `compose.proxy-only.yml` through
its saved `COMPOSE_FILE`. Admin Wi-Fi is disabled and both dashboard containers
have been removed. The built-in `ir-ap` broadcasts `Infrareveal`; Ethernet
provides SSH management and the uplink. The existing data and GeoIP mounts are
retained. A full reboot confirmed automatic recovery, healthy API/DNS and
advancing capture with no reported drops. See the
[single-radio validation report](../validation/single-radio-raspberry-pi.md)
for image identity, regression tests, evidence and operating commands.

**15 October update:** the `data-refactor` release `fb86b7c` is deployed from
`/home/pi/Documents/infrareveal-releases/fb86b7c`. Use `docker-compose.yml` plus
`compose.release.yml`, project `infrareveal`, and the `debug` profile. Its fresh
application data directory is `/home/pi/Documents/infrareveal/data-map-activity`;
the existing PocketBase administrator account and GeoIP assets are retained.
The seven core collections are enabled, diagnostics/trace/gate are disabled,
and demo mode keeps a 30-minute window. The route engine is `scamper`.
The host runs kernel `6.1.21-v8+` with its existing ARMv7 userspace and images.

The frontend build required converting the lockfile to the pinned pnpm version,
removing the obsolete luma.gl patch, and copying the shared test fixtures into
the dashboard build. These deployment fixes are present in the release worktree
and the local working tree; they are not part of commit `fb86b7c`. Build and
verification evidence is in `output/pocketbase-restructuring/pi-deployment-2026-10-15/`.
When editing an existing `.env`, replace every occurrence of a changed key and
inspect the effective Compose volumes before starting the services.

All three ARMv7 images built, and all 101 frontend tests passed in clean build
containers. After reboot, the API, both dashboards, map/block reads, revision
stream, DNS and both AP interfaces passed checks; the same demo session resumed.
Browser checks covered the live map and activity views without console errors.
The follow-up [physical client browsing test](../validation/client-browsing-e2e.md)
on `pi@192.168.10.139` joined the participant AP and loaded six public SVT and
Wikipedia pages. Its first run captured 5.46 MB with complete coverage and no
reported drops, populated map destinations and separated the SVT revisit into
a new activity block. Sustained adapter stability and physical admin Wi-Fi
client connectivity remain unverified.

**8 October update:** commit `85d30a6` is deployed from
`/home/pi/Documents/infrareveal-releases/85d30a6`, using `docker-compose.yml` plus
`compose.release.yml` and the `debug` profile. Compose `2.39.4` is installed;
the radios are named `ir-ap` and `ir-admin`. The original checkout and persistent
data remain in `/home/pi/Documents/infrareveal`. Use the
[deployment and rollback report](../validation/raspberry-pi-deployment-2026-10-08.md)
for that historical installation; verify the current Compose project before replacing it. The September inventory and initial setup steps
below describe its earlier state.

Checked on 2026-09-17:

- SSH: `pi@192.168.10.120` (this Ethernet DHCP address can change).
- Raspberry Pi 4 Model B, Raspberry Pi OS Bullseye **32-bit**, Docker 20.10.12.
- Built-in `brcmfmac` radio: `wlan0`, already broadcasting `Infrareveal`.
- Ralink RT5370 USB adapter: `wlan1`, driver `rt2800usb`, AP support advertised.
- Repository: `/home/pi/Documents/infrareveal`.
- Old container: `infrareveal-server`.
- Existing database: `/home/pi/Documents/infrareveal/data`, mounted at
  `/root/pb/pb_data`. The map/activity rewrite requires a fresh directory, such as `data-map-activity`.
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
reset unrelated local edits. Use a fresh application data directory for this rewrite.

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
mkdir -p data-map-activity geoip
nano .env
# Set DATA_DIR=./data-map-activity for the new schema.
```

The `Infrareveal-admin` Wi-Fi password is always **`password123`**. No password
file or Compose secret is needed. Existing `secrets/admin-wifi-password` files
are ignored. This is the Wi-Fi password; a fresh PocketBase database needs a
new superuser account. `.env`, `data` and `geoip` are
excluded from Git and the Docker build context.

In `.env`, use the verified current radio names (`ir-ap` / `ir-admin` on the
8 October installation) and country `SE`. Optionally set
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

## 5. Replace the build against fresh application data

Stop the current gateway before starting the replacement: both own the same
interfaces and firewall. Use the current deployment's Compose files and project
name when stopping it; the historical release may use `compose.release.yml`.
Do not launch two gateway containers on the same radios.

```bash
cd /home/pi/Documents/infrareveal
# Stop the verified current deployment first, then start the new build.
sudo docker compose stop
sudo docker compose up -d --no-build
sudo docker compose ps
sudo docker compose logs --tail=100 proxy dashboard
```

Set `DATA_DIR=./data-map-activity` before starting. A new empty directory creates
seven core application collections. `DIAGNOSTICS_ENABLED=true` creates ten;
the explicitly enabled gate also requires its audit collection. Keep the licensed
GeoIP assets. Old development recordings are disposable and are not imported.
The previous source remains in Git; an older version can use a fresh database
for its own schema. No parallel old/new data path is required.

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

For the single-radio Pi, use its current release directory and saved
`COMPOSE_FILE` above. Rebuild only the gateway image and run
`sudo docker compose up -d --no-build proxy`; retain the proxy-only override and
`ADMIN_WIFI_ENABLED=false` across releases.

For a full two-radio checkout:

```bash
cd /home/pi/Documents/infrareveal
git pull --ff-only
sudo bash scripts/build-pi-images.sh
sudo docker compose stop
sudo docker compose up -d --no-build
sudo docker compose ps
```

Keep `.env`, the selected new `DATA_DIR`, and `geoip` between updates. `restart: always` starts the
services again after reboot. The gateway waits for its enabled radios, then
validates configuration and starts the network. With `ADMIN_WIFI_ENABLED=false`,
the admin radio is completely excluded from startup and runtime checks. In the
default two-radio mode, a USB adapter plugged in after startup is also supported.
While a required radio is missing, the proxy is unhealthy. Dashboard containers
start independently and wait for the gateway API before binding the admin
address, so firewall isolation is installed before they begin serving requests.
Rebuild all three images when upgrading to this recovery behavior.

Every two seconds, a watchdog checks enabled radios, their interface identities,
and gateway addresses. Losing or replacing a required radio stops the gateway
daemons and lets Compose restart the proxy. It waits for the adapter to return,
then restores addresses, Wi-Fi, DNS and the API. This interrupts both Wi-Fi
networks and observation during recovery. Health checks also require enabled radios
to be in AP mode and the API to respond. USB enumeration failures still require
reseating or replacing the adapter; application recovery cannot repair hardware.

The current health check does not prove that a radio can transmit. An RT5370 can
remain present, UP and in AP mode while USB protocol errors leave traffic stuck;
the local API can still report healthy. Repeated `rt2800usb` errors, malformed
receive frames or `No buffer space available` need USB/driver investigation.
See the [2026-10-01 investigation](usb-wifi-diagnosis-2026-10-01.txt) for the
reproduced failure, hardware comparisons and proposed repair sequence.

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
python3 scripts/test-gateway-runtime.py
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

## Always-on lab demo and rolling sessions

Use the [lab demo guide](lab-demo.md). Set `DEMO_MODE=true` and
`DEMO_RETENTION_MINUTES=30`, rebuild/recreate, then open `http://10.77.0.1/demo`.
A live continuous session reuses its identity across a process restart. An ended
session stays ended; a new demo session receives a new identity. Network quota
charges survive both restart and session deletion.

Set `ephemeral` and `retention_minutes` on a session for rolling capture. Only
active continuous sessions advance `retained_from_ms`. `started_ms` is immutable.
Every 15 seconds cleanup removes expired traffic samples and coverage, preserves
crossing block identities and original starts, and retains applicable route
anchors. A paused playhead clamps when its retained window expires. Saved
recordings retain product history until deletion.

Storage follows traffic volume and the retained window. SQLite reuses deleted
pages, so database file size may remain above its live payload size. Diagnostic
storage has independent age/byte limits. There is no permanent domain catalogue,
raw connection requirement or old-data conversion. Docker logs rotate at 10 MiB
with three files per service, and consumed DNS spool data is bounded at 8 MiB.
