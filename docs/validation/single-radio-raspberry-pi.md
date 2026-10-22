# Single-radio Raspberry Pi deployment

Date: 22 October 2026. Host: `pi@192.168.10.120`.

The original deployment below used a loopback-only API. The later LAN access
update at the end of this report supersedes that binding and release path.

The admin USB adapter was removed. The previous proxy waited indefinitely for
`ir-admin`; the participant AP was down and the backend API was unavailable.
The replacement runs only the proxy, using built-in radio `ir-ap`, SSID
`Infrareveal`, and Ethernet for the uplink and SSH management.

## Deployment

- Release directory: `/home/pi/Documents/infrareveal-releases/fb86b7c-single-radio-20261022`.
- Image: `infrareveal-gateway:fb86b7c-single-radio-20261022`.
- Image ID: `sha256:aa999792f29162bc7b2941325035b538e4d49bdca67aff4f6d339c1e2761f90c`.
- Base image: the verified `fb86b7c` gateway, ID
  `sha256:8de4928add48165bb4117bce4ff6586f79cf26a459a411622f1152a7166ca815`.
- The image replaces only the entrypoint and three gateway network/runtime
  scripts. The Go binary remains byte-identical, SHA-256
  `5a856caeabda865b0db76616f4c1e13ce6d212bd961bb66d3609b54253a64b37`.
- `.env` pins `COMPOSE_FILE=docker-compose.yml:compose.release.yml:compose.proxy-only.yml`,
  clears `COMPOSE_PROFILES`, and sets `AP_IFACE=ir-ap` and
  `ADMIN_WIFI_ENABLED=false`. The proxy-only override also fixes the latter to
  false. Plain `docker compose up -d` selects only `proxy`.
- Both dashboard containers were stopped and removed. Their images remain
  available. No admin AP, resolver, address, firewall exception or NAT rule is
  created, including when an admin adapter is plugged back in.
- Existing application data and GeoIP bind mounts are retained. The saved
  `DEMO_MODE=false` setting is preserved; the existing active 30-minute rolling
  session `uthmsjbfbawavh6` resumes through normal session lifecycle handling.

These runtime changes are local modifications on top of `fb86b7c`, mirrored in
the development branch; they are not represented by that Git commit alone.

## Checks

- Five preflight tests and eleven runtime/supervisor tests pass on the Pi.
  New cases cover a missing admin adapter, ignoring a reconnected admin adapter,
  starting exactly the participant AP/resolver/backend, and retaining participant
  failure detection and API health requirements.
- Disposable Linux containers with private network namespaces pass both
  two-radio and single-radio tests: NAT, management isolation, repeatable
  firewall rules, DNS, and absence of admin rules/configuration when disabled.
- Shell entrypoint and static privacy checks pass. No backend Go code changed.
- Live verification checks the exact image and binary, one proxy container,
  one AP and resolver, healthy loopback API, public DNS resolution through the
  participant resolver, advancing capture coverage, no reported capture drops,
  no admin network rules, and no dashboard listeners.
- A full host reboot passed the same verification, with a new boot ID, zero
  container restarts, only the built-in AP, and the same active session resumed
  under a new capture epoch. Both dashboard containers remained absent. The
  backend API returned HTTP 200 and capture reported complete coverage with zero
  drops. Participant DNS returned public answers.

The forwarding checks use isolated virtual interfaces. This deployment check
does not repeat the six-page physical-client browsing test or establish
long-term radio stability.

## Evidence and operation

Local evidence is in `output/pocketbase-restructuring/single-radio-2026-10-22/`:
the runtime-update Dockerfile, test/build/deployment logs, verification script,
and `before-reboot.json` / `after-reboot.json`. The release's
`deployment-evidence/` directory retains these results along with the build
inputs, source hashes and verification script.

```sh
ssh pi@192.168.10.120
cd /home/pi/Documents/infrareveal-releases/fb86b7c-single-radio-20261022
sudo docker compose ps
sudo docker compose up -d --no-build
sudo python3 deployment-evidence/verify.py
```

Use Ethernet SSH for management. The PocketBase console remains reachable
through `ssh -L 8090:127.0.0.1:8090 pi@192.168.10.120`, then
`http://127.0.0.1:8090/_/`. There is no admin Wi-Fi or frontend dashboard service.
The previous release and image remain available, but starting their unmodified
two-radio configuration would restore the missing-adapter dependency.

## Later LAN access update

PocketBase now listens on `0.0.0.0:8090`; the gateway firewall permits port 8090
through the Ethernet uplink interface. Anyone on that LAN can use
`http://192.168.10.120:8090` and the PocketBase console at `/_/`. The local
dashboard selects this backend with `VITE_POCKETBASE_URL` in `.env.local`.

The current release is `/home/pi/Documents/infrareveal-releases/2f6480c-lan-api-20261022`,
using image `infrareveal-gateway:2f6480c-lan-api-20261022`. It replaces only the
entrypoint and firewall script in the verified single-radio image. The Go binary
and data mounts are unchanged. Only the proxy runs, with the admin radio and both
dashboard containers still disabled.

Both disposable network tests passed on the Pi: direct Ethernet API access,
participant isolation, NAT, repeatable firewall rules and DNS. All eleven runtime
tests passed locally and on the Pi. After recreation, the proxy is healthy with
zero restarts and the same active session resumed with complete capture and zero
reported drops. From the Mac, the health API, session manifest, CORS preflight,
live revision stream and PocketBase console all work directly. Vite serves the
Pi backend URL. Evidence is in `output/pocketbase-restructuring/lan-api-2026-10-22/`;
the release's `deployment-evidence/` also records its Dockerfile and source diff.

The existing `restart: always` policy and saved Compose configuration retain this
setup across restarts. A second host reboot was not required for this update.
