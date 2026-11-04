# Shared Wi-Fi Raspberry Pi deployment

Date: 4 November 2026. Host: `pi@192.168.10.120`.

Commit `564e93edb16aabc0a2faa3e46d232eb93213183c` is deployed in
`/home/pi/Documents/infrareveal-releases/564e93e-shared-wifi-20261104`.
The built-in `ir-ap` broadcasts `Infrareveal`; Ethernet supplies the uplink.
Participants and visiting display computers use this one Wi-Fi network. Open
`http://infrareveal.home.arpa` (fallback `http://10.0.0.1`) and choose **Use this
device as display** to exclude that device's new traffic from observation.

## Release and preserved state

The Pi's older source checkout contains local changes, so deployment uses a
separate detached Git worktree. Its saved Compose configuration selects
`docker-compose.yml:compose.release.yml:compose.shared-wifi.yml`, clears
`COMPOSE_PROFILES`, and sets `ADMIN_WIFI_ENABLED=false` and
`DASHBOARD_ON_AP=true`. Only the gateway and main dashboard run.

The Go applications were cross-compiled for Linux ARMv7 with CGO disabled; both
frontends were built with the same-origin API setting `VITE_POCKETBASE_URL=/`.
No Docker images were built on the development computer. Runtime images were
assembled on the Pi from its verified existing gateway and nginx images,
replacing the application binaries, frontend assets and relevant startup/config
files. Each image carries the deployed source revision label. The release keeps
the Dockerfiles, build artifacts and SHA-256 manifest in `runtime-artifacts/`.

| Image | ID |
| --- | --- |
| `infrareveal-gateway:564e93e-shared-wifi-20261104` | `sha256:4cf1552372647925b655abc17143f9144e2d17993be23c2d8ae3ed52d8070d84` |
| `infrareveal-dashboard:564e93e-shared-wifi-20261104` | `sha256:294b3ddbfb3333b531a9901e17c5f74afb41d12c2bf9780cba5e1a7864273f29` |

An updated debug dashboard image is available under the same release tag but
its service remains disabled. Data and GeoIP mounts remain, respectively,
`/home/pi/Documents/infrareveal/data-map-activity` and
`/home/pi/Documents/infrareveal/geoip`. The existing active session
`uthmsjbfbawavh6` resumed with its existing 30-minute rolling retention. The
saved `DEMO_MODE=false` setting was preserved; this does not change the existing
session's own rolling-retention settings.

Before switching, SQLite online backups of `data.db` and `auxiliary.db` both
passed `integrity_check`. They and the previous deployment configuration are in
`/home/pi/Documents/infrareveal-backups/20261104-before-shared-wifi`, readable
only by root. The previous release and images remain available.

## Verification

- Local Go tests and targeted race checks passed for display registration,
  gateway integration, capture exclusions and lab-gate behavior. Frontend
  builds, lint and all 102 workspace tests passed. Browser checks against a
  local DHCP fixture covered entering display mode, refresh, stopping and the
  mobile layout.
- On the Pi, fresh privileged containers with private network namespaces passed
  `scripts/test-gateway-network.sh` for shared Wi-Fi, proxy-only and separate
  admin Wi-Fi configurations. These checks cover dashboard access, backend-port
  restrictions, internet NAT, repeatable firewall setup and local DNS.
- The deployed gateway was healthy before and after a full host reboot. The
  boot ID changed from `09c37076-4fbd-4d47-b07e-9de157417ec8` to
  `890608c4-a2e5-468c-a730-cc856a30205f`. Both services started automatically
  with zero container restarts; only the built-in AP was present.
- Post-reboot checks verified matching binary and served-asset hashes, nginx
  configuration, API health, session/map/block reads, realtime revision events,
  the local hostname resolving to `10.0.0.1`, and upstream DNS answers.
  Capture was running with advancing confirmation times, complete coverage and
  zero reported drops. Requests from loopback without a participant DHCP lease
  could not register as a display.
- A browser loaded the deployed sessions page over an SSH tunnel, including the
  new display control and existing live session. Its live map also loaded, with
  no console errors on either page.

The verifier is saved as `verify-deployment.py` in the release, with results in
`after-reboot.json`. Local copies and browser evidence are in
`output/shared-wifi-deployment-2026-11-04/`.

No physical Wi-Fi clients were connected during deployment. The virtual-network
checks and local role fixture do not establish physical display/participant
separation, roaming behavior or long-term radio stability. Complete the
[physical acceptance steps](../implementation-guides/shared-wifi-display.md#verification)
with two Wi-Fi devices before relying on those properties at an event.

## Operation and rollback

```sh
ssh pi@192.168.10.120
cd /home/pi/Documents/infrareveal-releases/564e93e-shared-wifi-20261104
sudo docker compose ps
sudo docker compose up -d --no-build
sudo python3 verify-deployment.py
```

To return to the preceding proxy-only configuration, stop the new dashboard and
recreate the proxy from the saved old release. This keeps current data; it does
not restore an older database snapshot or delete newer recordings.

```sh
cd /home/pi/Documents/infrareveal-releases/564e93e-shared-wifi-20261104
sudo docker compose stop dashboard
sudo docker compose rm -f dashboard
cd /home/pi/Documents/infrareveal-releases/2f6480c-lan-api-20261022
sudo docker compose up -d --no-build proxy
```

The rollback restores the single-radio proxy-only setup. Ethernet SSH and the
LAN backend at `http://192.168.10.120:8090` remain the management path.
