# InfraReveal on Raspberry Pi

This guide shows how to run InfraReveal on a Raspberry Pi as a Wi‑Fi access point that transparently proxies HTTP/HTTPS traffic, stores metadata in PocketBase, and serves a dashboard.

What you get
- A Wi‑Fi AP on wlan0 (default SSID: Infrareveal)
- DHCP on 10.0.0.0/24 (dnsmasq), gateway at 10.0.0.1
- NAT to the internet via eth0 by default
- Transparent TCP proxy on port 1337 capturing hostnames and flow sizes
- PocketBase API/Admin on port 8090, dashboard on port 8080

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

Clone the repo on the Pi and optionally seed PocketBase data so collections exist on first run.

```bash
git clone https://github.com/hci-gu/infrareveal.git
cd infrareveal

# Seed PB data (recommended on first run)
mkdir -p data
cp -R pocketbase/pb_data/* data/ 2>/dev/null || true
```

Configuration knobs (via env in `docker-compose.yml`):
- AP_IFACE: AP Wi‑Fi interface (default wlan0)
- INTERNET_IFACE: uplink interface (default eth0)
- SSID: Wi‑Fi network name (default Infrareveal)

You can also tweak:
- `hostapd.conf` for country_code, channel, security (currently open)
- `dnsmasq.conf` for DHCP range and DNS behavior

## Run

Build and start with Compose (the proxy service is built locally; dashboard is pulled as an image):
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
	 - If this is the first run and you didn’t seed `data/`, create an admin user here and set up collections as needed.

Tip: The proxy redirects TCP port 80/443 from wlan0 into its transparent proxy (port 1337) to observe hostnames and byte counts, then forwards traffic.

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
	- First run: ensure collections exist (seeded `data/` or create via Admin UI)
	- The dashboard container image must support your Pi’s architecture; if it doesn’t, you can run the dashboard on another machine and point it to the Pi’s PocketBase URL

## Ports and data

- Dashboard: http://<pi-ip>:8080
- PocketBase API/Admin: http://<pi-ip>:8090 and http://<pi-ip>:8090/_/
- Persistent data: `./data` on the host is mounted to `/root/pb/pb_data` in the proxy container

## Security and ethics

This setup inspects traffic metadata on an open Wi‑Fi network. Use only with consent, in lab/education contexts, and comply with local laws and policies.

