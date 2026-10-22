# Map and activity rewrite validation

Completed 2026-10-15 against the implementation in this working tree. The
[implementation checklist](../../implementation-plan.md) is complete. The accepted
contract is [ADR 0003](../adr/0003-map-activity-storage.md).

The results below describe the original rewrite acceptance. Later checks include
the successful [physical-client browsing run](client-browsing-e2e.md) on 15 October
and [single-radio proxy deployment](single-radio-raspberry-pi.md) on 22 October.

## Result

Fresh core startup creates seven application collections: `sessions`,
`traffic_chunks`, `capture_intervals`, `activity_blocks`, `destinations`,
`route_evidence` and `probe_runs`. Full diagnostics creates ten. PocketBase auth
and system collections are excluded; enabling only the Lab gate adds its required
audit collection. Both profiles were bootstrapped and checked directly. The default
local `pocketbase/pb_data` was also reset to the seven-collection model and seeded
with an example recording.

Capture, route persistence, product queries and both dashboards now use the new
model. The old migrations, per-flow product stores, frontend reconstruction,
collection subscriptions and compatibility fixtures were removed. Existing
recordings are disposable; there is no conversion or parallel data path.

## Automated and browser checks

| Check | Result and scope |
| --- | --- |
| Go tests | `go test ./...` and the final `go test -race ./...` passed across all backend packages. |
| Frontend tests | 101 passed: 8 shared session-state, 38 map dashboard and 55 debug dashboard. |
| Workspace checks | `pnpm lint` and `pnpm build` passed. |
| Supported targets | Linux ARM64 and ARMv7 cross-builds passed; the final ARM64 gateway Docker image built successfully. |
| Native Pi tests | Cross-compiled observer, gateway and timeline test binaries passed on the ARMv7 Pi. Raw-socket cases were exercised separately through the capture smoke test. |
| Linux packet capture | Real receive-loop tests covered original packet lengths, large TCP/UDP/IPv6 frames, idle heartbeats and shutdown. |
| Network fixtures | Isolated gateway NAT/isolation, NFQUEUE fail-open, and Scamper TCP/UDP-Paris/ICMP-Paris method and terminal-boundary checks passed. |
| Operational scripts | Privacy/entrypoint checks, gateway preflight/runtime tests and demo-tool tests passed. |
| Real API browser | Recorded map, both projections, block evidence, paused live time, unavailable capture, debug activity details, Lab navigation and revision-stream cleanup passed with no page exceptions or retired API requests. |
| Optional diagnostics | Browser authentication and seeded DNS display passed. A final API check returned one row inside its selected time window, zero outside, and rejected invalid authentication and missing/oversized windows. |
| Schema and changes | Seven core/ten full collections verified; `git diff --check` passed. |

The focused contracts cover byte conservation through correction, playback and
retention; repeated/overlapping service activity; ACK-only traffic; shared IPs;
unknown evidence; capture gaps; tuple/lease reuse; bounded-cache eviction; stale
flushes; lifecycle drain; restart within a chunk; and backwards clock movement.
Route tests cover admission before execution, charged failures/cancellation,
restart and deletion quotas, silent/no-gain stopping, bounded evidence and
historical expiry/invalidation. Pagination tests keep a stable result while live
capture advances and invalidate it after clear, retention or an epoch change.

The incremental block projector is checked against the pure full projection
through classification, coverage, confidence, retention and restart changes.
The steady-state benchmark uses 30 minutes, 20 service bindings and 720,000 source
bins. It measured approximately **2.94 ms/op, 1.77 MB allocated/op and 11,023
allocations/op** on the development machine. It replays the correction tail;
its work does not rescan all sealed history. This is a development benchmark,
not a Pi measurement.

The first ARMv7 run exposed timestamp truncation from PocketBase `GetInt` on a
32-bit platform. Timestamp, revision and unbounded counter reads now use
`GetInt64`; the final Pi tests and capture smoke passed after that correction.

## Real capture smoke on the Pi

The final ARMv7 binary ran on the reachable Raspberry Pi 4 gateway, using its
Linux 5.10.92-v7l+ kernel and Docker 20.10.12. The test used a disposable container
with three private network namespaces and real AF_PACKET capture. It had no
external network route and did not replace or restart the existing deployment.

Five 128 KiB HTTP downloads passed through the gateway, with synthetic DNS
evidence and deliberately unavailable conntrack. The check observed provisional
chunks, sealing, idle coverage, several blocks, and a restart inside the same
five-second chunk. All paginated map and block results were checked against
stored counters. The fixture kept 50 ms samples and five-second chunks, shortening
the correction horizon to two seconds and the block quiet gap to one second to
exercise transitions in a brief run.

| Measurement | ARM64 development container | Raspberry Pi 4 / ARMv7 |
| --- | ---: | ---: |
| Smoke duration | 18.05 s | 17.57 s |
| Download body bytes | 655,360 | 655,360 |
| Capture drops | 0 | 0 |
| Current / peak RSS | 28.7 / 32.7 MiB | 25.4 / 25.4 MiB |
| Backend CPU time, across both process epochs | 1.04 s | 3.19 s |
| Average CPU, fraction of one core | 5.76% | 18.18% |
| Logical capture flushes | 45 (2.49/s) | 41 (2.34/s) |
| Process write bytes | 2,480,150 | 2,314,240 |
| Initial database + WAL bytes | 457,328 | 457,328 |
| Final database + WAL bytes | 1,028,088 | 1,048,688 |
| Final chunks / coverage intervals / blocks / destinations | 3 / 2 / 3 / 1 | 4 / 2 / 3 / 1 |
| Map read mean / maximum, ten requests | 1.55 / 3.74 ms | 10.20 / 20.24 ms |

Wire and captured payload-byte totals include protocol overhead and any
retransmissions; they are not expected to equal the HTTP body length. Logical
flush counts, process I/O and database/WAL growth are distinct measurements.
SQLite checkpointing and startup affect these brief storage measurements; do not
extrapolate them into daily storage rates.

The Pi's existing deployment already reported a missing `ir-admin` Wi-Fi adapter,
and the participant interface was down. Consequently this validates the new
backend on the actual Pi with virtual interfaces, **not physical Wi-Fi forwarding**.
It also does not establish sustained throughput, Internet route visibility or a
long retention soak. Those remain device acceptance procedures in
[Pi capture validation](flow-activity-raspberry-pi.md), rather than requirements for
keeping an old implementation alive.

## Reproduction and local evidence

Run the regular checks from the repository root:

```sh
pnpm test
pnpm lint
pnpm build
cd pocketbase
go test ./...
go test -race ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build ./...
go test -run '^$' -bench BenchmarkRebuildBlocksThirtyMinutes -benchmem ./observer
```

Use [`scripts/dev-data.sh`](../../scripts/dev-data.sh) for disposable core or
diagnostics databases and the [browser procedure](../../dashboard/test-support/README.md)
for actual product API checks. The default reset requires stopping the local
server first.

The new [`scripts/test-map-activity-netns.sh`](../../scripts/test-map-activity-netns.sh)
produces capture, storage and resource evidence. For an ARM64 Docker host, from
the repository root:

```sh
docker build --platform linux/arm64 -t infrareveal-gateway:map-activity .
mkdir -p output/pocketbase-restructuring/map-activity-netns
docker run --rm --privileged --network none --entrypoint bash \
  -e IR_MAP_ACTIVITY_ISOLATED=1 \
  -v "$PWD:/workspace:ro" \
  -v "$PWD/output/pocketbase-restructuring/map-activity-netns:/results" \
  infrareveal-gateway:map-activity \
  /workspace/scripts/test-map-activity-netns.sh /root/pb/infra-reveal /results
```

For ARMv7, use its cross-built binary and a matching runtime image. The script
requires explicit isolation and refuses an outer default route. It creates and
removes only its own namespaces.

Generated evidence is ignored by Git under `output/pocketbase-restructuring/`:
`go-race-final.log`, `docker-gateway-final.log`, `browser-final.log`,
`map-activity-netns/report.json` and `pi-map-activity/report.json` with adjacent
capture logs and response fixtures. The Pi binary SHA-256 is
`6192d373a071a6144326524c8d4218dbb5c7aeead5b81c40d21c367226c2646e`.

## Code size

`python3 scripts/count-loc.py` compares the complete working tree, including new
nonignored files, against `85d30a60185d057c9077c7445c68c196d147a34f`.
This includes the earlier staged refactor as well as this rewrite.

| Physical lines | Before | After | Change |
| --- | ---: | ---: | ---: |
| Production source | 25,106 | 19,365 | −5,741 |
| Maintained scope, including tests/configuration/fixtures | 40,281 | 31,075 | −9,206 |
| All non-documentation, including locks and migrations | 44,791 | 34,350 | −10,441 |

Documentation is excluded from these totals. Removed tests and fixtures described
the retired contracts; current aggregate, lifecycle, route and browser checks
cover the replacement.
