# Raspberry Pi deployment — 8 October 2026

Deployed commit `85d30a60185d057c9077c7445c68c196d147a34f` to
`pi@192.168.10.120`. The gateway and both dashboards start successfully, recover
after reboot, and retain the existing installation. Automated ARMv7 and isolated
kernel checks passed. Physical client browsing remains unverified: no participant
or admin Wi-Fi station reconnected during the post-upgrade checks.

## Installation and rollback

- Raspberry Pi 4 Model B Rev 1.4, Bullseye 32-bit, kernel `5.10.92-v7l+`,
  Docker `20.10.12`, Compose `2.39.4`.
- Active release: `/home/pi/Documents/infrareveal-releases/85d30a6`, a detached
  worktree of the pushed commit. The original checkout at
  `/home/pi/Documents/infrareveal` still contains its original local edits and
  untracked files; its status was compared before and after deployment.
- Compose project remains `infrareveal`. Run it with both `docker-compose.yml`
  and `compose.release.yml`, and the `debug` profile.
- Original configuration was copied privately. Persistent mounts remain
  `/home/pi/Documents/infrareveal/data` and `/home/pi/Documents/infrareveal/geoip`.
- Interfaces remain `ir-ap`, `ir-admin` and `eth0`. Demo mode and its 30-minute
  retention remain enabled; route engine remains `v2`. Trace and Lab gate
  remain disabled, matching the previous deployment.
- All three ARMv7 images were built locally, labeled with the full Git revision,
  transferred to the Pi and pinned by release tag before interrupting services.

| Image tag | Image ID prefix |
| --- | --- |
| `infrareveal-gateway:85d30a6` | `184e7e23848d` |
| `infrareveal-dashboard:85d30a6` | `3ea7ad995cdf` |
| `infrareveal-debug-dashboard:85d30a6` | `480bde8461fd` |

The complete data directory was copied **after stopping the old services** to
`/home/pi/infrareveal-backups/20261008-before-85d30a6/data`. That directory also
holds the original environment, Compose file, image IDs, worktree patch/status,
database comparison and rollback script. Each original image has a
`before-85d30a6-20261008` tag; existing image tags were retained.

Inspect the running release:

```bash
cd /home/pi/Documents/infrareveal-releases/85d30a6
sudo docker compose --profile debug -p infrareveal \
  -f docker-compose.yml -f compose.release.yml ps
```

If rollback is needed:

```bash
bash /home/pi/infrareveal-backups/20261008-before-85d30a6/rollback.sh
```

The script stops the services, preserves post-upgrade data in a separate dated
directory, restores the stopped backup and starts the retained images. It was
prepared but not invoked against the live installation. Separately, the previous
gateway image successfully opened a transactionally consistent copy of the
upgraded database in a container with no external network, preserving ordinary
record hashes and session identities.

## Verification

| Check | Result |
| --- | --- |
| Native ARMv7 Go tests | All **200 distinct named tests** passed, including gated Linux tests run in their required environments |
| Gateway network namespaces | Management isolation, subnet separation, NAT, repeatable firewall setup, resolver configuration and admin DNS passed |
| Actual Pi kernel packet capture | Idle cancellation and original-length accounting passed for large IPv4 TCP/UDP and IPv6 UDP frames |
| Actual Pi kernel route probing | Legacy and structured TCP/UDP/ICMP probes, reply loss, IPv6, NAT, cancellation, seven diagnostic profiles and silent-target time budget passed |
| Actual Pi kernel NFQUEUE | Listener bypass, delayed accept, explicit drop, listener termination with a held packet, queue pressure and recovery passed |
| Database preservation | SQLite quick checks passed before/after deployment and after reboot; all ordinary session-scoped table counts and raw row hashes match |
| Existing sessions | Same three IDs and modes: two recordings and the resumed demo; 205 historical flows and 384 historical DNS records preserved |
| Catalogue | All 464 existing domains retained |
| API | Health, demo, all three manifests, bounded detail windows, pagination, route status and disabled gate status passed |
| Reboot | SSH returned after about 33 seconds; all three containers restarted automatically and the gateway became healthy; demo resumed the same ID |
| Running networking | Both interfaces report AP mode and the configured SSIDs/addresses; both live DNS resolvers answered an external A query successfully |
| Management access | Both dashboards return HTTP 200 through the admin interface; Ethernet connections to ports 80, 8081 and 8090 are rejected |
| Browser against deployed services | Session libraries, historical map data, pause/seek/speed, return to live, Traffic and recorded Lab replay/node inspection passed |
| Six-minute health sample | 25 samples: no API/database/maintenance/capture errors; database size stayed at 37,130,240 bytes; WAL stayed at or below 4,128,272 bytes |

Kernel integration tests ran in disposable privileged containers with isolated
network namespaces, never in the live gateway network namespace. Test binaries
were cross-compiled from the deployed commit and executed on the Pi. The first
NFQUEUE harness attempt stopped because the minimal runtime image lacks
`sysctl`; the successful run used the equivalent `/proc/sys` write and a
precompiled `nfqueue-smoke` binary. Application code was unchanged.

After reboot the services showed zero automatic restarts. One post-validation
sample measured gateway process RSS at 44,600 KiB and temperature at 45.7°C,
with `get_throttled=0x0` and 4.2 GiB free disk. Docker's old host combination
reports unusable zero memory figures, so RSS came from host `ps`. These are spot
measurements during idle/browser inspection, not a throughput or memory-soak
benchmark.

Browser checks used desktop Chromium through temporary SSH forwards to the Pi's
admin addresses. They establish deployed UI/API behavior, not display-Pi GPU
performance. Historical records without packet timing correctly display counter
estimates. The ordinary recording with flows rendered nine locations/tracks at
the inspected playback position.

## Findings and remaining checks

- **Physical client acceptance is still pending.** No station was associated
  after deployment/reboot, and no new client flow, DNS or packet activity was
  observed. Pre-upgrade traffic is not counted as evidence for this release.
  Verify participant association, DHCP, browsing/video, forwarding and fresh
  observations, then admin association/access and exclusion from capture.
- **Existing display issue:** the debug session library caps ephemeral duration
  at five minutes in `sessionSummaries.ts`, although the demo API, manifest and
  map correctly use 30 minutes. The same hard-coded cap exists in the previous
  deployed source (`7d64e0f`); it was not changed by this deployment.
- **Configured optional features:** live Lab trace requests return 404 while
  `DEBUG_TRACE_ENABLED=false`; replay remains available. The gate remains off.
  No live client traffic was intercepted or armed for testing.
- Complete the sustained workload/resource/retention matrix, physical flow/
  strict/DNS gate matrix, power-loss/USB-disconnect/storage-fault checks and
  target-display/browser matrix described in the existing
  [PocketBase](pocketbase-restructuring.md),
  [capture](flow-activity-raspberry-pi.md) and
  [Proxy Lab](proxy-lab-raspberry-pi.md) procedures. This target establishes
  ARMv7 results only, not hardware acceptance on an ARM64 installation.

Local logs, image builds, API samples and comparisons are under
`output/pocketbase-restructuring/pi-deployment-2026-10-08/`; screenshots are
`output/playwright/pi-20261008-*.png`. Pi-side test scripts and evidence are under
`/home/pi/infrareveal-validation/85d30a6/`. Generated artifacts are not committed.
