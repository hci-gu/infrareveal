# InfraReveal on Raspberry Pi

This guide shows how to run InfraReveal on a Raspberry Pi as a Wi‑Fi access point that records gateway metadata, stores observations in PocketBase, and serves a dashboard. It does not decrypt HTTPS traffic or require client trust certificates.

What you get
- Participant Wi-Fi on wlan0 (SSID: Infrareveal)
- WPA2-protected admin Wi-Fi on a second radio, wlan1 (SSID: Infrareveal-admin)
- DHCP on 10.0.0.0/24 (dnsmasq), gateway at 10.0.0.1
- NAT to the internet via eth0 by default
- DNS query observations from dnsmasq
- Flow observations from conntrack sampling
- Header-only, directional flow activity at 50 ms resolution (no payload or URL storage)
- Confidence-labeled flow attribution from recent DNS answers where available
- Destination context and route approximations for observed destination IPs
- Dashboard and PocketBase API/console at http://10.77.0.1/ on the admin network
- Optional debug dashboard at http://10.77.0.1:8081/

## Development guides

See the [documentation index](docs/README.md) for architecture decisions, current guides and repeatable validation procedures.

- [Flow activity bursts](docs/implementation-guides/flow-activity-bursts.md): implemented metadata-only capture and visualization of fine-grained traffic inside long-lived connections.
- [Flow activity validation](docs/validation/flow-activity-raspberry-pi.md): repeatable privacy, load, growth, and browser-comparison checks for the target Pi.
- [Proxy Lab implementation and operations](docs/implementation-guides/proxy-lab.md): passive replay/live tracing plus the opt-in flow, strict-packet, and DNS gates.
- [Proxy Lab Raspberry Pi validation](docs/validation/proxy-lab-raspberry-pi.md): namespace, failure, soak, client, and recovery procedures.
- [Dashboard browser validation](docs/validation/debug-dashboard.md): fixture, interaction, accessibility, performance and lifecycle checks.
- [Live route discovery](docs/implementation-guides/live-route-discovery.md): finite useful-path collection, topology display, budgets and diagnostics.
- [Live route validation](docs/validation/live-route-discovery.md): timing targets, cache/replay checks and pending Pi measurements.

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

Follow the **[two-network Pi deployment guide](docs/implementation-guides/pi-deployment.md)**
for the existing Pi at `pi@192.168.10.120`. It covers pulling changes, installing
Compose on its 32-bit OS, building images,
preparing host networking, backing up the existing database, and replacing the
old `infrareveal-server` container.

The gateway requires two AP-capable Wi-Fi radios and an Ethernet uplink. The
inspected built-in radio and Ralink RT5370 USB adapter meet the advertised
capabilities. Images support ARMv7 and ARM64; the Docker target platform selects
the Go binary architecture automatically. The host OS obtains Ethernet settings
through DHCP. Upstream authentication and subnet conflicts still need handling.

Join `Infrareveal-admin` with **`password123`** to open **http://10.77.0.1/** or
**http://infrareveal.home.arpa/**. The UI and API share that address; no Ethernet IP
needs to be discovered. Port 8090 is loopback-only. Participant devices continue
to use `Infrareveal`, with internet and observation on `10.0.0.0/24`.

## Configuration

Copy `.env.example` to `.env` as described in the deployment guide. Runtime scripts generate hostapd and the two dnsmasq
configurations from these settings; there are no hand-edited root-level AP configs.

Configuration knobs (via env in `docker-compose.yml`):
- AP_IFACE: participant Wi-Fi interface (default wlan0)
- ADMIN_IFACE: admin Wi-Fi interface (default wlan1)
- ADMIN_WIFI_MAC: optional expected adapter MAC address
- ADMIN_SSID: admin Wi-Fi name (default Infrareveal-admin)
- AP_PREFIX / ADMIN_PREFIX: private /24 prefixes (10.0.0 / 10.77.0), checked for collisions
- WIFI_COUNTRY / AP_CHANNEL / ADMIN_CHANNEL: SE / 1 / 6
- DATA_DIR / GEOIP_DIR: persistent host directories (./data / ./geoip)
- INTERNET_IFACE: uplink interface (default eth0)
- SSID: Wi‑Fi network name (default Infrareveal)
- ROUTE_ENGINE: `v2` (Scamper, default), `legacy` (paced traceroute), or `off`; all active engines share the same limits
- ROUTE_MAX_TARGETS / ROUTE_MAX_ATTEMPTS: 20 targets / 40 automatic attempts per session
- ROUTE_HOURLY_ATTEMPTS: 40 per network and address family, across sessions/restarts
- ROUTE_MAX_SNAPSHOTS / ROUTE_MAX_BYTES: 100 useful path snapshots / 16 MiB evidence per session
- ROUTE_ASN_DB: optional versioned local MaxMind ASN database; missing ASN data leaves the topology visible
- CLIENT_CIDRS / GATEWAY_IP / PACKET_ACTIVITY_IFACE: derived from the participant prefix/interface by the container entrypoint; admin traffic is excluded
- Discovery uses one worker at five probes/second, at most two methods per selected binding, and stops after useful evidence or repeated no-gain results. Missing hops never trigger indefinite repairs.
- CONNTRACK_SAMPLE_MS: connection sampling interval, validated to 250–5000 ms (default 1000)
- PACKET_ACTIVITY_ENABLED: enable header-only packet activity capture (default true)
- PACKET_ACTIVITY_IFACE: capture interface (defaults to AP_IFACE)
- PACKET_ACTIVITY_BUCKET_MS: activity resolution, validated to 20–1000 ms (default 50)
- PACKET_ACTIVITY_CHUNK_SECONDS: sparse persistence chunk size (default 5)
- PACKET_ACTIVITY_RETENTION_HOURS: retention for inactive-session detail (default 24)

### Proxy Lab: passive trace vs traffic gate

Proxy Lab lives only in the debug dashboard at `/proxy-lab/:sessionID`. Passive trace is observation-only. It streams bounded, header-derived events and can be enabled independently with `DEBUG_TRACE_ENABLED=true`; no NFQUEUE policy is installed when lab gate support is disabled.

The lab gate is a separate, explicit traffic-changing experiment. `LAB_GATE_ENABLED=true` makes the three fail-open NFQUEUE listeners and empty rule chains available, but still does not gate a client. An authenticated operator must arm selected IPv4 clients for an active session. Flow mode holds new TCP/UDP flows, strict mode steps one exact tuple in both directions, and DNS mode gates selected traffic to local dnsmasq. See the [operator guide](docs/implementation-guides/proxy-lab.md#safe-first-run) before enabling it.

| Variable | Default / bounds | Safety effect |
|---|---|---|
| `DEBUG_TRACE_ENABLED` | `false` | Enables bounded passive SSE tracing only. |
| `DEBUG_TRACE_RING_EVENTS` | `20000` (`100`–`200000`) | Caps in-memory replay history. |
| `DEBUG_TRACE_RETENTION_SECONDS` | `30` (`5`–`300`) | Caps live trace age. |
| `DEBUG_TRACE_INGRESS_BUFFER` | `8192` (`128`–`131072`) | Full buffer rejects trace events; forwarding is unaffected. |
| `DEBUG_TRACE_SUBSCRIBER_BUFFER` | `256` (`8`–`4096`) | A slow viewer drops its own trace stream rather than blocking capture. |
| `DEBUG_TRACE_BATCH_MS` | `50` (`10`–`1000`) | Coalescing latency. |
| `DEBUG_TRACE_MAX_BATCH` | `200` (`1`–`200`) | Caps one SSE payload. |
| `DEBUG_TRACE_MAX_SUBSCRIBERS` | `32` (`1`–`256`) | Caps viewer memory. |
| `LAB_GATE_ENABLED` | `false` | Master opt-in; false leaves no effective queue policy. |
| `LAB_GATE_QUEUE_NUM` | `42` | Flow-mode queue; must differ from 43/44. |
| `LAB_GATE_STRICT_QUEUE_NUM` | `43` | Exact-tuple packet queue. |
| `LAB_GATE_DNS_QUEUE_NUM` | `44` | Local DNS INPUT queue. |
| `LAB_GATE_CLIENT_SUBNET` | Derived from `AP_PREFIX` | Only participant IPv4 clients can arm. |
| `LAB_GATE_MAX_PENDING_FLOWS` | `128` (`1`–`1024`) | New decisions bypass when full. |
| `LAB_GATE_MAX_HELD_PACKETS` | `768` (`8`–`8192`, at least pending cap) | New packets bypass when full. |
| `LAB_GATE_FLOW_TIMEOUT_MS` | `10000` (`100`–`60000`) | Pending flows are accepted as expired. |
| `LAB_GATE_ESTABLISHED_TIMEOUT_MS` | `500` (`100`–`10000`) | Strict packets are accepted quickly. |
| `LAB_GATE_DNS_TIMEOUT_MS` | `2000` (`100`–`15000`) | DNS is accepted before indefinite resolver stalls. |
| `LAB_GATE_DECISION_CACHE_SECONDS` | `120` (`1`–`900`) | Bounds remembered flow verdicts. |
| `LAB_GATE_FAIL_OPEN` | `true` | Arming is refused when false. |
| `LAB_GATE_CONTROL_TOKEN_FILE` | unset | Mutating controls are refused without a 32–512 byte token file. |
| `LAB_GATE_ALLOWED_ORIGINS` | unset | Comma-separated browser origins allowed to call the control API. |

## Run after initial setup

```bash
sudo bash scripts/build-pi-images.sh
sudo docker compose up -d --no-build
sudo docker compose ps
sudo docker compose logs --tail=100 proxy dashboard
```

Uncomment `COMPOSE_PROFILES=debug` in `.env` to include the debug dashboard.
For updates to an existing installation, use the guide's stopped-state database
backup procedure before restarting with new images.

## Using it

1) Join `Infrareveal-admin` on the operator device using `password123`.
2) Open http://10.77.0.1/ (dashboard) or http://10.77.0.1/_/ (PocketBase console).
3) Join `Infrareveal` on the device being observed. It receives a `10.0.0.50–150`
   address and internet via the Pi. Generate traffic to view it in the dashboard.

Admin traffic has internet forwarding but is excluded from capture and DNS
observations. The two subnets cannot forward to each other. Management web ports
are inaccessible from participant Wi-Fi and Ethernet. The UI/API work locally
without an uplink; the basemap still downloads internet-hosted tiles and fonts.

The gateway forwards web traffic normally through NAT. Classic DNS traffic from clients is redirected to the local dnsmasq resolver so transaction-linked DNS answers, including CNAME chains, can be correlated with flows. Stored flows are limited to remote traffic initiated by connected clients; gateway-generated probes and local infrastructure traffic such as DNS sockets, DHCP, NTP, PCP, mDNS, and traceroute are excluded. The dashboard keeps raw destination IPs visible and labels inferred hostnames with confidence.

The activity overlay passively counts packet headers on the AP interface into sparse directional buckets. Pale bars remain conntrack connection lifetimes; amber and cyan marks show client-to-remote and remote-to-client transfer activity. The gateway immediately discards the bounded packet prefix used for parsing and stores only counts, times, tuple keys, flags, and byte totals. It does not store packet contents or claim that encrypted bursts are HTTP resources or response times. Hatched regions mean capture was missing or lossy and are excluded from idle-time calculations.

For supported site/app families, the backend also derives conservative activity episodes. Confirmed first-party and CNAME-linked flows are grouped directly; a third-party hostname is associated only when the same client freshly resolves and opens it within a short window of confirmed activity. The original endpoint is always preserved, inferred children are visibly marked, and provider-only, unresolved, pre-existing, DNS-less, or ambiguous traffic is left independent.

Destination context is enriched independently from reverse DNS, known provider networks, and the bundled GeoIP database. Slow traceroute work runs separately so it cannot delay identity labels. Routes are traceroute approximations from the gateway to the observed destination IP and port; they are not exact proof of the client application path.

## Always-on lab demo

For an unattended screen, enable `DEMO_MODE=true`, set
`DEMO_RETENTION_MINUTES=30`, and open **http://10.77.0.1/demo** on the admin PC.
The dedicated session resumes after restarts; the screen follows live traffic and
reconnects automatically. A separate domain catalogue preserves bounded examples
and aggregate counts for reviewing `domain_groups.json`.
See the [lab demo setup, exports, and soak-test guide](docs/implementation-guides/lab-demo.md).

## Always-on sessions

In the PocketBase admin console at **http://10.77.0.1/_/**, open `sessions`,
edit the current session, enable **ephemeral**, and save. It stays active and both
dashboards show a rolling timeline (five minutes by default; configure
`retention_minutes` in the session). Old observations are discarded
on a 15-second cleanup cycle; live connections and the evidence they need remain.
Regular sessions keep their existing recording behavior.

Enabling this on an existing recording discards its older history. Disable
`ephemeral` to resume keeping history from the remaining window, or to stop the
session. See the [deployment guide](docs/implementation-guides/pi-deployment.md#always-on-ephemeral-sessions)
for storage and upgrade details.

## Customizations

Set SSIDs, country/channels, interface names, and non-overlapping private network
prefixes in `.env`. Run `sudo docker compose up -d --no-build --force-recreate`
after changing runtime settings. Changing the admin prefix changes the dashboard
address too. Reconnect clients after changing prefixes so DHCP leases renew.
The admin Wi-Fi password is always `password123`; no secret file is required.
Both radios are dedicated APs in this deployment.

## Troubleshooting

- hostapd failed to start
	- Ensure the Wi‑Fi chip supports AP mode
	- Set the correct `WIFI_COUNTRY` in `.env`
	- Make sure `wpa_supplicant` is disabled and not holding wlan0

- dnsmasq failed to start
	- Confirm `wlan0` exists and is up, and no other DHCP server runs on the host
	- The container will set 10.0.0.1/24 on wlan0; conflicting host configs can break this

- No internet from clients
	- Verify `INTERNET_IFACE` (default eth0) actually has internet
	- Check NAT rules and IP forwarding in `proxy` logs

- Dashboard loads but shows no data
	- Verify PocketBase is reachable through http://10.77.0.1/api/health on admin Wi-Fi
	- Confirm a client has generated DNS or network traffic after joining the AP
	- Check that `/var/log/dnsmasq.log` and `/proc/net/nf_conntrack` are visible inside the container
	- Review `docker compose logs dashboard proxy` and confirm the proxy is healthy

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

- Dashboard/API: http://10.77.0.1/ on admin Wi-Fi
- PocketBase console: http://10.77.0.1/_/
- Optional debug dashboard: http://10.77.0.1:8081/
- Persistent data: `./data` on the host is mounted to `/root/pb/pb_data` in the proxy container
- GeoIP assets: `./geoip` is mounted read-only at `/root/geoip`

## Security and ethics

This setup inspects traffic metadata on an open Wi‑Fi network. Use only with consent, in lab/education contexts, and comply with local laws and policies.
