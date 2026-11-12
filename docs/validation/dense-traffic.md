# Dense traffic validation

The supported demo layout is 20+ participant browsing devices and one shared
dashboard on a display computer. Size traffic by packet rate, simultaneously
active client/service/destination bindings, and retained history. Device count
alone does not establish capacity. The load generator below exercises the real
parser, attribution, queue, aggregation, storage and product read API without
sending network traffic. It cannot establish Wi-Fi airtime or forwarding capacity.

## Implementation contract

- Map reads use pinned, expiring read transactions and bounded keyset pages.
  Compact pages combine exact bindings/evidence and conserve all six counters.
  Raw detail, coverage, blocks and route evidence retain independent pagination.
- Finalized 30-second browser segments are reused. Only the mutable correction
  tail is replaced; epoch, policy and retention changes invalidate stale data.
  Segment indexes reuse historical byte totals and waveform contributions.
- History resolution follows the selected span; the 15-second playhead window
  keeps source resolution. This changes display resolution, never stored counts.
- Sidebars and location details render the viewport with overscan. Service
  details page through 20 series. The timeline builds at most 32 mounted lanes;
  totals, membership and common scale still include every matching contributor.
- Capture writes only changed provisional rows using prepared statements and a
  commit-aware cache. The consumer drains its queued batch before a delayed
  flush. Background passive WAL checkpoints avoid routine writer-side syncing.
- Default publication is 1,000 ms, with 32,768 queued packet events and 16,384
  pending contributions. These are bounded buffers, not throughput guarantees.
  The dashboard explicitly reports capture lag and cumulative missed events.

See [map rendering](../implementation-guides/map-dashboard.md) and
[backend ownership](../implementation-guides/pocketbase-architecture.md) for the
cache, cursor and lifecycle details.

## Reproduce recorded density

Use a new directory for each fixture. Never point the generator at production
data. `--reuse` requires its existing `workload.json` marker and serves that
fixture without regenerating it.

```sh
cd pocketbase
go run ./cmd/traffic-load --dir ../output/traffic-scale/1500 \
  --clients 30 --bindings 50 --minutes 5 --bins 5 --serve --http 127.0.0.1:8092
```

From the repository root, check the complete five-minute response against the
independently calculated fixture totals:

```sh
python3 scripts/measure-traffic-load.py --url http://127.0.0.1:8092 \
  --output output/traffic-scale/1500-api.jsonl --window-seconds 300 \
  --expected output/traffic-scale/1500/workload.json
```

For the larger case use `--clients 50 --bindings 100 --minutes 30 --bins 5`
and a new directory. This generates 5,000 series, 1.8 million source chunks and
nine million occupied source bins; allow about 1 GiB of database space. Use
`--window-seconds 1800 --resolution 5000` for its complete-history API check.

Build the production dashboard against the isolated API and serve it on 5197.
Open a Playwright CLI session, then run the repeatable browser check:

```sh
VITE_POCKETBASE_URL=http://127.0.0.1:8092 corepack pnpm --dir dashboard build
corepack pnpm --dir dashboard exec vite preview --host 127.0.0.1 --port 5197
# Separate terminal:
corepack pnpm dlx @playwright/cli -s=density open http://127.0.0.1:5197 --headed
DASHBOARD_ORIGIN=http://127.0.0.1:5197 GATEWAY_ORIGIN=http://127.0.0.1:8092 \
  TRAFFIC_HISTORY_MINUTES=30 node dashboard/test-support/run.mjs browser-dense-traffic density
```

The check verifies all expected tracks are present, bounded DOM while scrolling,
timeline playback, pause latency, both projections, retained data after returning
to the map, failed reads and browser exceptions. Frame cadence is measured in a
visible foreground browser; it depends on the display computer and GPU. Use the
separate shader/motion checks for renderer correctness. Development React builds
are unsuitable for comparing dense playback performance.

## Live Pi soak

Build `./cmd/traffic-load` for the Pi's kernel architecture. It owns its isolated
database and listener. The November 2026 Pi has a 64-bit kernel with a 32-bit
userspace; the static ARM64 binary runs on that kernel.

```sh
./traffic-load --dir /home/pi/infrareveal-load/90m \
  --clients 30 --bindings 10 --pps 2000 --minutes 30 \
  --duration 90m --http 127.0.0.1:8095
```

This offers 2,000 packets/s across 300 continuously active bindings and retains
30 minutes. DNS attribution is refreshed during the run. Scheduler delays do not
silently lower the offered rate: the generator accounts for elapsed ticks, and
`source-stats.json` records independent offered packet/byte counts. At completion
capture drains and the fixture becomes a closed recording; the API stays up for
inspection. Do not confuse this workload with 1,500 continuously active bindings.

Keep a production-build dashboard open against the isolated API. From the Pi,
run a health/resource sample each second and a complete 15-second read every
ten seconds (replace `PID` and paths):

```sh
python3 scripts/measure-traffic-load.py --url http://127.0.0.1:8095 \
  --output health.jsonl --samples 6000 --interval 1 --window-seconds 0 \
  --pid PID --database /home/pi/infrareveal-load/90m/data.db \
  --source-stats /home/pi/infrareveal-load/90m/source-stats.json --stop-on-ended
python3 scripts/measure-traffic-load.py --url http://127.0.0.1:8095 \
  --output tail.jsonl --samples 600 --interval 10 --window-seconds 15 \
  --source-stats /home/pi/infrareveal-load/90m/source-stats.json --stop-on-ended
```

Assess the full run and the steady state after retention has begun: offered
rate, capture drops, capture-confirmation age, read latency/errors, CPU, RSS,
database/WAL growth and browser memory. File allocation may plateau above live
data size because SQLite reuses free pages. An RSS high-water mark is not current
RSS. Measure browser memory after comparable garbage collection points.

Targets are zero capture drops, capture-confirmation p95 below two seconds,
playback above 30 fps, and common controls below 200 ms. Capture-confirmation age
is a backend measure: displayed freshness additionally includes revision delivery,
read and render time. Keep both distinct in reports. Large cold history loads are
also separate from steady-state live latency.

## Acceptance evidence

The implementation has passed all 141 workspace tests, frontend lint, production
builds, backend tests and the race detector for data, capture, timeline and
gateway packages. Regression coverage includes all six counters beyond the old
4,000-row limit, pinned revisions during concurrent correction, independently
paged large route records, retention, failed-commit retries, cache invalidation,
segment index equivalence and capture health messages.

The 5,000-series / 30-minute production browser run on the development computer
loaded in 35.8 seconds, mounted 20 sidebar rows and 32 timeline lanes, and had no
failed map requests. Five-second measured frame cadence was 103 fps for the
timeline, 113 fps for Equal Earth, and 68 fps for Mercator. Pause-to-paint was
44 ms. Mercator had initialization/GC stalls (maximum 749 ms); these averages
are not a guarantee of hitch-free playback on other display hardware. The API
fixture checks preserved the expected traffic totals.

The deployment report records the final Pi soak and operational checks. A
physical rehearsal with 20+ browsing devices remains necessary: synthetic
capture does not exercise the Wi-Fi radio, NAT forwarding, upstream Internet,
real destination mix or the actual presentation screen.
