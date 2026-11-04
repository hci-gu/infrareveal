# Live dashboard Raspberry Pi deployment

Date: 4 November 2026. Host: `pi@192.168.10.120`.

Application commit `f824be688e2f3ee86f44fd0d446fd51029d05965` runs from
`/home/pi/Documents/infrareveal-releases/f824be6-live-dashboard-20261104`.
It keeps loaded data visible during compatible live refreshes and defaults live
lists to latest activity. Join `Infrareveal` and open
`http://infrareveal.home.arpa` (fallback `http://10.0.0.1`).

## Release and preserved state

The existing checkout has local changes, so deployment uses a separate detached
worktree. Only the gateway and main dashboard run under Compose project
`infrareveal`, using `docker-compose.yml:compose.release.yml:compose.shared-wifi.yml`.
The debug dashboard and admin radio remain disabled; the built-in `ir-ap` and
Ethernet uplink retain the shared Wi-Fi configuration.

Go binaries were cross-compiled for Linux ARMv7 with CGO disabled, and both
frontends were built with `VITE_POCKETBASE_URL=/`. No Docker images were built on
the development computer. Runtime images were assembled on the Pi from the
previous release's verified gateway and nginx images, replacing application
binaries, assets and startup/configuration files. Each image carries the
application revision label. Artifacts, Dockerfiles and SHA-256 hashes are in the
release's `runtime-artifacts/` directory.

| Image | ID |
| --- | --- |
| `infrareveal-gateway:f824be6-live-dashboard-20261104` | `sha256:d2a1d26571161bfded4ecb32c9f3dbf187b471491614a729f7c7d7fd17380759` |
| `infrareveal-dashboard:f824be6-live-dashboard-20261104` | `sha256:80de6604b0f0d8e2441c357901c1cb1edde58e8ab647c3d7741a25698c4a9eac` |

An updated debug dashboard image is also available under the release tag.
Persistent data and GeoIP mounts remain
`/home/pi/Documents/infrareveal/data-map-activity` and
`/home/pi/Documents/infrareveal/geoip`. The existing active session
`uthmsjbfbawavh6` resumed with its 30-minute retention. Existing runtime settings,
including `DEMO_MODE=false`, were preserved.

Before switching, online SQLite backups of `data.db` and `auxiliary.db` passed
integrity checks. They, the previous configuration, container details and a
rollback script are in the root-only directory
`/home/pi/Documents/infrareveal-backups/20261104-before-f824be6-live-dashboard`.
The original checkout's local changes are unchanged.

## Verification

- All 112 workspace tests, frontend lint/builds, and `go test ./timeline ./gateway`
  passed before deployment. Local browser fixtures covered delayed refreshes,
  failed requests and recovery, latest-first lists, both map projections and the
  mobile layout.
- Both deployed containers run the intended revision with zero restarts. Gateway
  health, nginx configuration and read-only database checks passed. All 18 served
  dashboard assets and both Go binaries match the release hashes.
- The existing session remained active. Map and activity APIs returned data;
  latest-first block ordering and invalid-order rejection passed. Revision events
  arrived through nginx. Capture confirmation advanced with complete current
  coverage and no error. The cumulative drop counter was 32,968, with no increase
  during the four-second capture check; this was not a zero-drop session.
- The shared AP was active with two connected stations. The local dashboard name
  and upstream DNS resolved, and the existing dashboard/API firewall rules were
  present.
- A browser loaded the real live session through an SSH tunnel. Over 35 seconds,
  including a rolling-window refresh, 143 DOM observations detected no empty
  states, missing location rows or missing totals. Latest activity was selected
  by default, and the browser reported no errors or warnings.

The release contains `verify.py` and `verification.json`. Local evidence is in
`output/live-dashboard-deployment-2026-11-04/`, with the browser script, result
and screenshot in `output/playwright/pi-live-*`. This update did not repeat the
previous release's host reboot or physical display/participant acceptance tests.

## Operation and rollback

```sh
ssh pi@192.168.10.120
cd /home/pi/Documents/infrareveal-releases/f824be6-live-dashboard-20261104
sudo docker compose -p infrareveal ps
sudo docker compose -p infrareveal up -d --no-build
sudo python3 verify.py
```

To return to the previous shared Wi-Fi application release while keeping current
data:

```sh
sudo /home/pi/Documents/infrareveal-backups/20261104-before-f824be6-live-dashboard/rollback.sh
```

The rollback recreates the gateway and dashboard using the previous release's
images and configuration. It does not restore an older database snapshot.
