# InfraReveal on Raspberry Pi

This guide shows how to run InfraReveal on a Raspberry Pi as a Wi‑Fi access point that records gateway metadata, stores observations in PocketBase, and serves a dashboard. It does not decrypt HTTPS traffic or require client trust certificates.

What you get
- A Wi‑Fi AP on wlan0 (default SSID: Infrareveal)
- DHCP on 10.0.0.0/24 (dnsmasq), gateway at 10.0.0.1
- NAT to the internet via eth0 by default
- DNS query observations from dnsmasq
- Flow observations from conntrack sampling
- Header-only, directional flow activity at 50 ms resolution (no payload or URL storage)
- Confidence-labeled flow attribution from recent DNS answers where available
- Destination context and route approximations for observed destination IPs
- PocketBase API/Admin on port 8090, dashboard on port 8080

## Development guides

- [Flow activity bursts](docs/implementation-guides/flow-activity-bursts.md): implemented metadata-only capture and visualization of fine-grained traffic inside long-lived connections.
- [Flow activity validation](docs/validation/flow-activity-raspberry-pi.md): repeatable privacy, load, growth, and browser-comparison checks for the target Pi.

## Frontend workspace

The regular dashboard and debug dashboard are pnpm workspace consumers of
`@infrareveal/session-state`. The shared package owns PocketBase transport,
normalized session entities, realtime reconciliation, temporal indexes,
windowed detail caching, and playback state. Each dashboard keeps its own UI
and Remotion projection.

```bash
pnpm install
pnpm build
pnpm test
pnpm lint
```

Run an individual dashboard with `pnpm --filter @infrareveal/dashboard dev` or
`pnpm --filter @infrareveal/debug-dashboard dev`. Set `VITE_POCKETBASE_URL`
when PocketBase is not on port 8090 of the dashboard host.

Note: The AP is open (no password) by default. Use only in controlled environments.

## Prerequisites

- Raspberry Pi 3B+/4/5 with built‑in Wi‑Fi (AP mode capable) or a USB Wi‑Fi adapter that supports AP mode.
- Ethernet uplink on eth0 (or a second Wi‑Fi adapter for uplink).
- Raspberry Pi OS 64‑bit recommended (see Architecture note). Up‑to‑date firmware/drivers.
- Docker Engine and Compose plugin installed on the Pi.

Install Docker and Compose on the Pi
```bash
curl -fsSL https://get.docker.com | sh
sudo usermod -aG docker $USER
sudo apt-get update
sudo apt-get install -y docker-compose-plugin
# log out/in or run: newgrp docker
```

## Architecture note (arm64 vs armhf)

The provided Dockerfile builds an arm64 (aarch64) Go binary. Ensure your Pi runs a 64‑bit OS and Docker can run arm64 images. If you must run 32‑bit (armhf):
- Change GOARCH in the Dockerfile to `arm`
- Use a 32‑bit base image (e.g., a balenalib armv7 image)

Otherwise, keep the default and use a 64‑bit Raspberry Pi OS.

## Network expectations

- AP interface: wlan0, static 10.0.0.1/24
- DHCP range: 10.0.0.50 – 10.0.0.150
- Uplink: eth0 by default (configurable)
- Ports exposed on the Pi:
	- 8080 → Dashboard (HTTP)
	- 8090 → PocketBase API/Admin (HTTP)

## Configure the project

Clone the repo on the Pi. PocketBase migrations create the required collections on first run.

```bash
git clone https://github.com/hci-gu/infrareveal.git
cd infrareveal
```

Configuration knobs (via env in `docker-compose.yml`):
- AP_IFACE: AP Wi‑Fi interface (default wlan0)
- INTERNET_IFACE: uplink interface (default eth0)
- SSID: Wi‑Fi network name (default Infrareveal)
- PACKET_ACTIVITY_ENABLED: enable header-only packet activity capture (default true)
- PACKET_ACTIVITY_IFACE: capture interface (defaults to AP_IFACE)
- PACKET_ACTIVITY_BUCKET_MS: activity resolution, validated to 20–1000 ms (default 50)
- PACKET_ACTIVITY_CHUNK_SECONDS: sparse persistence chunk size (default 5)
- PACKET_ACTIVITY_RETENTION_HOURS: retention for inactive-session detail (default 24)

You can also tweak:
- `hostapd.conf` for country_code, channel, security (currently open)
- `dnsmasq.conf` for DHCP range and DNS behavior

## Run

Build and start with Compose:
```bash
docker compose up -d --build
```

Check logs if something doesn’t start:
```bash
docker compose logs -f proxy
docker compose logs -f dashboard
```

## Using it

1) On a client device, connect to the AP SSID (default: Infrareveal). It should receive an IP in 10.0.0.50–150 and have internet via the Pi.
2) Visit the dashboard: http://<pi-ip>:8080
3) PocketBase Admin UI: http://<pi-ip>:8090/_/

The gateway forwards web traffic normally through NAT. Classic DNS traffic from clients is redirected to the local dnsmasq resolver so transaction-linked DNS answers, including CNAME chains, can be correlated with flows. Stored flows are limited to remote traffic initiated by connected clients; gateway-generated probes and local infrastructure traffic such as DNS sockets, DHCP, NTP, PCP, mDNS, and traceroute are excluded. The dashboard keeps raw destination IPs visible and labels inferred hostnames with confidence.

The activity overlay passively counts packet headers on the AP interface into sparse directional buckets. Pale bars remain conntrack connection lifetimes; amber and cyan marks show client-to-remote and remote-to-client transfer activity. The gateway immediately discards the bounded packet prefix used for parsing and stores only counts, times, tuple keys, flags, and byte totals. It does not store packet contents or claim that encrypted bursts are HTTP resources or response times. Hatched regions mean capture was missing or lossy and are excluded from idle-time calculations.

For supported site/app families, the backend also derives conservative activity episodes. Confirmed first-party and CNAME-linked flows are grouped directly; a third-party hostname is associated only when the same client freshly resolves and opens it within a short window of confirmed activity. The original endpoint is always preserved, inferred children are visibly marked, and provider-only, unresolved, pre-existing, DNS-less, or ambiguous traffic is left independent.

Destination context is enriched independently from reverse DNS, known provider networks, and the bundled GeoIP database. Slow traceroute work runs separately so it cannot delay identity labels. Routes are traceroute approximations from the gateway to the observed destination IP and port; they are not exact proof of the client application path.

## Customizations

- Change SSID without editing files by overriding the env in `docker-compose.yml`:
	```yaml
	environment:
		- AP_IFACE=wlan0
		- INTERNET_IFACE=eth0
		- SSID=MyLabAP
	```
- Use a second USB Wi‑Fi as uplink: set `INTERNET_IFACE=wlan1` and keep AP on `wlan0`.
- Secure the AP: add WPA2 config in `hostapd.conf` (psk/ieee80211w, etc.).
- Change DHCP range: edit `dnsmasq.conf`.

## Troubleshooting

- hostapd failed to start
	- Ensure the Wi‑Fi chip supports AP mode
	- Set correct `country_code` in `hostapd.conf` and host OS WLAN country
	- Make sure `wpa_supplicant` is disabled and not holding wlan0

- dnsmasq failed to start
	- Confirm `wlan0` exists and is up, and no other DHCP server runs on the host
	- The container will set 10.0.0.1/24 on wlan0; conflicting host configs can break this

- No internet from clients
	- Verify `INTERNET_IFACE` (default eth0) actually has internet
	- Check NAT rules and IP forwarding in `proxy` logs

- Dashboard loads but shows no data
	- Verify PocketBase is reachable at http://<pi-ip>:8090
	- Confirm a client has generated DNS or network traffic after joining the AP
	- Check that `/var/log/dnsmasq.log` and `/proc/net/nf_conntrack` are visible inside the container
	- The dashboard container image must support your Pi’s architecture; if it doesn’t, you can run the dashboard on another machine and point it to the Pi’s PocketBase URL

- Dashboard shows `Counters unavailable`
	- Conntrack byte accounting is disabled or not writable from the observer container
	- The observer tries to enable `/proc/sys/net/netfilter/nf_conntrack_acct` on startup; restart the proxy after updating
	- Existing conntrack entries created before accounting was enabled may stay at zero, so generate fresh client traffic after restart

- Dashboard shows hatched activity bars or a packet-capture warning
	- Check `docker compose logs proxy` for an actionable `packet activity capture unavailable` message
	- Confirm `PACKET_ACTIVITY_IFACE` names the client-facing AP interface, normally `wlan0`
	- The proxy needs its existing privileged/host-network configuration to open `AF_PACKET`
	- Hatching is intentional: unknown capture time is never reported as observed idle time

## Ports and data

- Dashboard: http://<pi-ip>:8080
- PocketBase API/Admin: http://<pi-ip>:8090 and http://<pi-ip>:8090/_/
- Persistent data: `./data` on the host is mounted to `/root/pb/pb_data` in the proxy container

## Security and ethics

This setup inspects traffic metadata on an open Wi‑Fi network. Use only with consent, in lab/education contexts, and comply with local laws and policies.
