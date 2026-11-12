# Dense traffic Raspberry Pi deployment

Date: 12 November 2026. Host: `pi@192.168.10.120`.

Application revision `bbd5466992d268f10ca0f847f0b53b72fa5a5963` runs from
`/home/pi/Documents/infrareveal-releases/bbd5466-dense-traffic-20261112`.
Join `Infrareveal`, open `http://infrareveal.home.arpa` (fallback
`http://10.0.0.1`), and choose **Use this device as display** on the shared screen.
Participants use the same Wi-Fi. The deployment preserves the existing recording,
30-minute retention, GeoIP data and shared-radio configuration. The final release
adds an advancing capture-lag warning and response-clock correction to the capture/storage implementation tested in `bc4d25a`. The
passive-only checkpoint experiment was reverted after unbounded WAL growth.

## Release and recovery

The Pi is a 4 GiB Raspberry Pi 4 with a 64-bit kernel and 32-bit userspace.
Statically linked ARM64 Go binaries were cross-compiled with CGO disabled.
Runtime images were assembled on the Pi from the existing verified ARMv7 images;
their networking utilities remain ARMv7. The gateway is privileged as in the
previous deployment and executes the ARM64 binaries on the host's 64-bit kernel.
The dashboard was built with `VITE_POCKETBASE_URL=/`.

The release's `runtime-artifacts/manifest.json` records hashes and revision labels.
It contains the binaries, dashboard assets, inherited startup/configuration files
and Dockerfiles. The debug dashboard image was built but its service remains off.

| Image | ID |
| --- | --- |
| `infrareveal-gateway:bbd5466-dense-traffic-20261112` | `sha256:77328f300053aec81833ad7a67eab1c0849256d785d9705646d3a17fed729c04` |
| `infrareveal-dashboard:bbd5466-dense-traffic-20261112` | `sha256:3ebd00fce4f3656e3ef9e478f5f01e599b4431b01b3ba15f8e9bbc0125b1b399` |

The existing checkout contains local changes, so deployment used a separate
detached worktree. Its source status was unchanged after deployment. Data and
GeoIP mounts remain `/home/pi/Documents/infrareveal/data-map-activity` and
`/home/pi/Documents/infrareveal/geoip`. The active session remains
`uthmsjbfbawavh6`; `DEMO_MODE=false` is preserved.

Online backups of both SQLite databases passed integrity checks. They, the old
configuration, container details and rollback script are in the root-only folder
`/home/pi/Documents/infrareveal-backups/20261112-before-0e4ad04-dense-traffic`.
Its name reflects the first build candidate; it backs up the actual preceding
`f824be6-live-dashboard-20261104` release.

```sh
ssh pi@192.168.10.120
cd /home/pi/Documents/infrareveal-releases/bbd5466-dense-traffic-20261112
sudo docker compose -p infrareveal ps
sudo python3 verify.py
# Roll back application images/configuration while keeping current data:
sudo /home/pi/Documents/infrareveal-backups/20261112-before-0e4ad04-dense-traffic/rollback.sh
```

## Functional verification

- All 143 workspace tests, frontend lint and production builds passed. Backend
  tests passed, including capture, pagination, correction, retention, shutdown
  and exact source-counter conservation. Race checks passed for storage,
  observation, timeline and gateway ownership.
- Both deployed containers were healthy/running with zero restarts. Database
  checks and nginx configuration passed. Both Go binaries and all 18 packaged
  dashboard files served through nginx matched the artifact hashes.
- The session remained active, capture confirmation advanced, and revision
  events arrived through nginx. Dashboard-name and upstream DNS resolved, the
  shared AP was active and the expected networking rules remained installed.
- A browser opened the actual deployed dashboard, switched view/settings and
  returned from the expanded timeline without an exception. The Pi had no
  associated participant stations during this check, so zero traffic was valid.
- The existing recording's cumulative missed-event counter was 64,644. It did
  not increase during the deployment capture check; this is not a historically
  lossless recording. The new banner reports that history explicitly.

`verification.json` and `verify.py` are in the release directory. Local evidence
is under `output/traffic-scale/`, with screenshots under `output/playwright/`.
See [dense traffic validation](dense-traffic.md) for the 5,000-series browser
results, exact-counter fixtures and reproducible commands.

## Sustained-load validation

The final isolated workload ran from **12:58:35 to 14:28:35 UTC** on 12 November,
using capture/checkpoint and load-tool revision `bc4d25a`. The deployed `bbd5466`
revision has identical storage, observation and timeline source; only the warning
and response clocks changed afterwards. The workload generated **5,399,962 packets**
(4,610,596,520 wire bytes, 999.993 packets/s) across 30 synthetic clients and 300
continuously active bindings, with 30-minute retention. The source completed and
drained with **zero reported capture drops**. This is a capture-path workload,
not traffic forwarded through the Wi-Fi/NAT path.

A production-build browser requested 30-minute history. Independent monitors
sampled health/resources every second and fetched a complete 15-second window
every ten seconds. There were 4,189 health observations and 496 completed window
reads, with **zero API errors**. Storage still generated 764 capture-flush busy
retries, two drain retries, 43 retention busy errors and three activity-block
busy errors. These recovered; they must not be mistaken for error-free storage.

| Measurement | Full run | Last 30 minutes |
| --- | --- | --- |
| Capture age, median / p95 / maximum | 0.828 / **9.865** / 27.119 s | 0.832 / **10.076** / 21.251 s |
| Process RSS, median / p95 / sampled maximum | 189 / 260 / 324 MiB | 211 / 249 / 284 MiB |
| CPU, average percent of one core | 86.5% | 94.2% |
| Database allocation | plateau at 125.53 MiB | 125.53 MiB throughout |
| WAL allocation | peak 338.43 MiB; reused thereafter | 190.73 MiB throughout |

The **two-second capture-freshness target failed**, including after retention
reached steady state (minutes 30–90 p95: 10.183 seconds). These capture ages
use the earlier server timestamp and can understate time spent waiting for a
response; they are not end-to-end screen freshness measurements. The final
clock fix makes the displayed warning more accurate without removing storage
latency. The process high-water mark was 337 MiB. Final temperature was 48.7°C
with no recorded throttling. One-minute disk samples after minute 30 showed
median 1.76 MiB/s writes and 66% busy time (p95 83%).

The complete tail reads took median 410 ms, p95 695 ms and maximum 6.65 seconds.
After capture stopped, all six counters for the final 30 minutes matched
independent SQLite sums exactly: 365,112,774 sent bytes; 1,171,714,520 received
bytes; 318,349,386 sent payload bytes; 1,124,952,500 received payload bytes;
899,988 sent packets; 899,962 received packets. The API read took 13 pages,
12.05 seconds and 4.35 MB. SQLite `quick_check` passed, and no sample preceded
the recorded retention floor. These retained-window counts intentionally exclude
the older traffic removed by retention.

Local raw evidence is in `output/traffic-scale/final-soak/`, including
`analysis.json`, `final-counters.json`, health/window/IO samples, source totals
and browser logs. Pi logs remain in
`/home/pi/infrareveal-load-20261112/soak-1000/`. After testing, the 32 owned fixture
databases were checkpointed, copied to
`output/traffic-scale/pi-fixture-archive/`, verified by SHA-256 and SQLite
`quick_check`, then removed from the Pi. This reclaimed 940,085,248 bytes;
2.1 GiB was available on the SD card after deployment. Production recordings,
GeoIP data, release backups and the original edited checkout were preserved.
The archive inventory records paths, sizes and hashes. Pi fixture markers were
renamed to `workload.archived.json` to prevent reuse from silently creating an
empty database; restore the archived files and original marker before reuse.

The existing SD card is fixed hardware for this deployment. A runtime-only
writeback experiment ran from 13:22:56 to 13:28:36 UTC, setting
`vm.dirty_background_bytes=1048576`. It did not demonstrate an improvement:
capture-age p95 was 15.40 seconds during the trial versus 9.09 seconds in the
preceding five minutes. These phases also differ in database age, so this is
not a controlled estimate of the setting's effect. The original values were
restored and verified (`dirty_background_bytes=0`,
`dirty_background_ratio=10`); no persistent sysctl change was installed.
All other dirty-page settings remained unchanged. The run's report separates
the trial from the original-settings phases. The threshold behavior is described
in the [Linux writeback documentation](https://docs.kernel.org/admin-guide/sysctl/vm.html#dirty-background-bytes).

At minute 30.6, the foreground display computer still showed all 300 tracks.
Five-second frame measurements were 114 fps in the expanded timeline,
119 fps in Mercator and 119 fps in Equal Earth. Pause-to-paint was 13 ms,
with 32 mounted lanes and no browser exceptions. These rendering measurements
do not imply that newly captured traffic was reaching the screen within two seconds.

A final display fix in `bbd5466` keeps capture-age warnings advancing without
server updates, even during paused playback. Manifest and revision-stream clocks
now use response time instead of a timestamp from before a potentially delayed
database read. Regression tests hold the database connection to check both API
clocks. A browser check paused playback and interrupted updates; the warning
advanced to 3.4 seconds without an exception. This check briefly used a second
browser around minutes 45–46. The capture implementation measured by the soak is
unchanged by this fix.

Browser heap after collection rose from 52 MiB at minute 31 to 82 MiB at minute
46. Heap inspection found the history cache bounded to 61 segments / 109,800
coarse samples (about 19.2 MiB estimated cache cost), with old segments expiring.
A deeper retention-path inspection around minutes 54–56 disrupted the automated
browser session. It was restored with 30-minute history and all 300 tracks;
capture continued throughout. This is **not** a successful 90-minute uninterrupted
browser endurance test, and a long-run browser heap plateau has not been proven.
The zero-track sample during the diagnostic reset is retained in the evidence
and excluded from any steady-state browser memory comparison.
A subsequent bounded object inspection at minute 61 found 83 traffic-window
objects, with no old recording history retained beyond the rolling window and
its boundary segments. Full heap snapshots were not repeated.
After recovery, heap samples at minutes 61–76 stayed between 65.8 and 67.6 MiB,
then fell to 49.9 MiB after capture ended. This supports bounded memory in that
shorter interval, without replacing an uninterrupted endurance test.
A late interaction check at minute 78.6 measured 59 fps in the expanded timeline
and 60 fps in Equal Earth, with a 25 ms pause response, 32 mounted lanes, all
300 tracks and no browser exceptions. The earlier check also covered Mercator.

Earlier runs exposed resource problems: waveform caches retained superseded tail
indexes, and passive checkpoints alone failed to reuse WAL space during sustained
capture. The final caches use weak identities and a byte budget. The checkpoint
worker coalesces updates over roughly five seconds, with varied timing, while
capture still publishes every second. Tests cover eviction correctness and WAL
reuse after a pinned reader finishes. Writer-side automatic checkpoints are
disabled while the worker owns them and restored on shutdown or worker failure.

A preceding 33.8-minute run of `e738b70` exposed long storage syncs: 15,256 packet
events had been missed by minute 27, before diagnostic instrumentation. Brief
system-call tracing then observed a database sync taking 10.77 seconds. That run
ended with 44,625 missed events; its final minutes include tracing overhead and
are not a clean throughput benchmark. The final release removes the size-based
writer checkpoint fallback. A subsequent passive-only experiment kept capture
fresh but grew the WAL continuously, even after dashboard reads were paused.
It was stopped before exhausting disk space. The deployed release therefore
keeps opportunistic zero-timeout `RESTART` to permit WAL reuse; this can still
hold the writer during a slow storage sync. The 2,000-packet/s target is **not
validated on this storage**. A 10.9-minute run of the final capture code
(`bc4d25a`) at 2,000 packets/s had zero drops and API errors, but capture-confirmation p95 was
3.79 seconds (maximum 10.48 seconds), missing the two-second target. Its WAL
allocation reached 119 MiB. This short run does not establish sustained lossless
capacity at that rate. The 90-minute run above evaluates 1,000 packets/s with
the same 300 active bindings, without tracing or image builds.

An earlier run during Docker image construction missed 5,956 packet events.
The UI showed backlog and loss, kept loaded traffic visible and recovered. That
period is retained as overload evidence, separate from the final steady-state
run. Build or update images before participants begin a demo on this SD card.

Physical rehearsal with 20+ browsing devices is still required. Synthetic
capture does not establish radio airtime, NAT forwarding capacity, real browsing
mix, upstream Internet performance or the actual presentation computer's GPU.
The native fullscreen operation was unavailable in the automated browser;
its graceful fallback was verified. This release did not repeat the host reboot
or physical display-role acceptance procedures.
