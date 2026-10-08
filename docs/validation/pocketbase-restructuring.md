# PocketBase restructuring validation

Candidate: working tree, 8 October 2026. Baseline: `ea3ec5f517ab5d845843f2f5367db10d35bee0ba`.
See the [architecture guide](../implementation-guides/pocketbase-architecture.md)
for current ownership and the [original plan](../proposals/pocketbase-restructuring.md)
for scope. No migration, collection rename, PocketBase upgrade or probe-engine
upgrade accompanies this restructuring.

The user confirmed that no test Pi is available and asked for the remaining
hardware checks to be documented. Physical gateway acceptance and deployment
remain unverified. Local namespace tests are isolated Linux evidence; cross-builds
establish compilation only. No live gateway or deployed recording was changed.

## Local verification

Environment: macOS ARM64, Go `1.27.1` selected by the module toolchain; Docker
Desktop Linux ARM64, Debian Bookworm, pinned `scamper=20211212-1.1` for kernel tests.

| Check | Result |
| --- | --- |
| `go test ./...` | Passed, including the actual registered hooks and armed-gate transitions |
| `go test -race ./...` | Passed, all packages |
| `go vet ./...` | Passed |
| `pnpm test` | Passed: shared session state 57, dashboard 95, debug dashboard 106 tests |
| `pnpm lint` and `pnpm build` | Passed; existing large-bundle warnings remain |
| Shared session-state tests after final route fixture correction | Passed, 57 tests |
| Linux ARM64 and ARMv7, CGO disabled, `go build ./...` | Passed |
| Production Dockerfile `builder` target for ARM64 | Passed, gateway and route diagnostic binaries built with the moved packages |
| Entrypoint and privacy scripts; Python preflight tests | Passed; three Python tests |
| Linux namespace route, packet capture and NFQUEUE checks | Passed on final source, including idle capture cancellation |
| Repeated Linux capture regression | Passed, 30 runs of capture/idle cancellation/original-length tests |
| Linux capture race check | Passed, three repetitions of the actual socket/original-length/cancellation tests |
| Existing-installation copy and read comparison | Passed against refreshed candidate source |

Logs and compatibility probes are retained locally under
`output/pocketbase-restructuring/` (ignored generated output). They are suitable
for attaching to a review or release, not a replacement for the hardware report.

The new integration regressions cover:

| Boundary | Evidence |
| --- | --- |
| Committed session selection | Registered create/update hooks, failed save, enclosing transaction rollback, restart selection and the actual multi-request PocketBase batch endpoint |
| Gate/session/clear ordering | Real controller and audit writer with synthetic queue: held packet accepts, gate disarms, terminal audit persists before session completion or clear deletion |
| Startup and shutdown | Inert construction, partial-start rollback, dirty packet retry/drain, retrying joins after deadlines, queue/probe worker completion |
| Clear | A blocked conntrack save prevents acknowledgement; after it finishes, records clear and the still-live tuple stays suppressed across several restarted polls; route reset rejects accepted old demand and late results |
| Observation derivation | DNS and flow records produce installed attribution and domain groups; rejected downgrades retain stronger evidence; unchanged passes preserve IDs and skip saves |
| Packet quality | Pending-flow matching, generation acknowledgement, write failure, bounded pressure, actual header-only capture and distinct unmatched versus lost events |
| Route transactions | Failed publication rolls back and retries without another admission; terminal accounting stays idempotent; manual/automatic spending and physical cancellation lease remain bounded |
| Retention | Live-flow/DNS dependencies, ordinary history, pre-window route/evidence anchors, route-engine-off cleanup, independent shared cutoffs and catalogue correction rollback |
| Maintenance failures | Failed catalogue aggregation does not stop inactive packet cleanup or shared route expiry |
| Transport contracts | Shared Go/TypeScript manifest, all window collections, current/legacy route evidence and gate identity fixtures; timeline, collection and realtime readers; all collection arrays survive activity batching |

These tests establish specific invariants. They do not measure sustained forwarding
performance, physical interface behavior, browser interaction on a Pi, or every
combination of shutdown and storage failure.

The final namespace rerun exposed a pre-existing raw-socket lifecycle bug. An idle
capture did not return after cancellation (three of three reproductions), and
repeated capture tests failed in 27 of 30 runs. Closing the socket from a separate
goroutine left a blocked receive and allowed the deferred second close to touch a
reused descriptor. Capture now owns its sole close and uses a 100 ms receive
timeout to check cancellation. The actual idle-socket regression and IPv4/IPv6
header-only capture pass in 30 repeated runs; capture tests also join their worker
before starting another. This is required for clear/shutdown completion, not a
change to observed traffic scope or packet contents.

## Existing-installation compatibility

An isolated checkout of the baseline created a database using its own migrations
and the shared ordinary-session fixture. After closing PocketBase, its data
directory was copied and opened by the refactored code. This is a synthetic
baseline installation, not a deployed historical database.

The comparison verifies:

- All 80 SQLite schema objects match exactly.
- Row counts and content hashes match across 29 non-internal SQLite tables,
  including all 25 migration rows; the foreign-key check reports no violations.
- All 15 fixture records across 13 collections have identical raw PocketBase
  exports, IDs and system timestamps after reopening.
- Manifest and all 11 timeline window collections match at a fixed clock.
  Request watermarks and system timestamps are excluded only from this timeline
  comparison; the raw-record and database comparisons include stored timestamps.

The fixture includes flow/DNS attribution, domain grouping, packet activity,
destination context, route revision with three evidence events and gate history.
Separate native tests exercise rolling retention, demo restart and catalogue
corrections. Opening a real installation containing ordinary, active, rolling and
demo sessions remains part of release acceptance below.

## Measured unchanged observation pass

The baseline and current code each warm one pass over the same one-flow,
one-DNS-answer fixture, then run an unchanged pass. PocketBase query logging counts
SELECTs; record hooks independently count derived creates/updates.

| Work per pass | Baseline | Refactored |
| --- | ---: | ---: |
| Application-data SELECTs | 9 | 5 |
| Relation-validation SELECTs | 7 | 0 |
| Collection-metadata SELECTs | 2 | 2 |
| Total SELECTs | 18 | 7 |
| Derived record saves | 3 | 0 |

Stored conclusions agree after normalizing generated IDs and system timestamps;
association references are compared through stable group keys. The current
production test additionally verifies unchanged record identities across passes.
This measurement is not a wall-clock speedup, CPU/RSS result or high-cardinality
benchmark. Destination heartbeat and other required writes remain separate.

## Reproduce local checks

From the repository root:

```bash
pnpm test
pnpm lint
pnpm build
(cd pocketbase && go test ./...)
(cd pocketbase && go test -race ./...)
(cd pocketbase && go vet ./...)
(cd pocketbase && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...)
(cd pocketbase && GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build ./...)
./scripts/test-entrypoint.sh
./scripts/check-proxy-lab-privacy.sh
python3 scripts/test-gateway-preflight.py
docker build --target builder --build-arg TARGETARCH=arm64 \
  --build-arg TARGETVARIANT= -t infrareveal-backend:restructure-builder .
```

For kernel checks, build `observer` and `routing` Linux test binaries for the
container's architecture. Run the following inside a disposable privileged Linux
container with `iproute2`, `iptables`, `ipset`, `tcpdump`, `traceroute`, Python, Go
and the pinned Scamper package. Mount the repository read-only; `nfqueue-smoke`
is built into the container's temporary directory by its script. Do not run these
namespace commands on a live gateway.

```bash
./scripts/test-route-coverage-netns.sh /testbins/routing.test
ip netns add ir-capture
trap 'ip netns del ir-capture 2>/dev/null || true' EXIT
ip -n ir-capture link set lo up
ip netns exec ir-capture env INFRAREVEAL_PACKET_CAPTURE_TEST=1 \
  /testbins/observer.test \
  -test.run 'TestPacket(Capture|Original)' -test.v
./scripts/test-lab-gate-netns.sh
```

Route checks exercise the real legacy and structured adapters, IPv4/IPv6, reply
loss, NAT, cancellation and all seven diagnostic profiles. Packet checks exercise
the actual BPF/socket/parser boundary, including the corrected IPv6 CIDR fixture.
NFQUEUE checks exercise bypass, delayed accept, drop, listener failure and cleanup.
The existing qualified IPv6 UDP limitation and ICMP approximation are unchanged;
see [route validation](live-route-discovery.md).

Compatibility artifacts include the baseline/current Go probes, full query logs,
SQLite snapshots, comparison scripts and source hashes. Their README explains
how to reconstruct isolated source copies and repeat the comparison. Never seed
or run these probes against the deployed data directory.

## Remaining physical gateway acceptance

All items below are pending. The blocker is the absence of a test Pi and an
offline copy of an actual deployed installation. No SSH target was supplied;
no deployment or live-network intervention was attempted.

1. **Existing installation and rollback.** Stop a dedicated test installation and
   preserve its image, configuration and complete data directory. Work on a copy
   containing an old ordinary recording, active session, rolling session, demo
   catalogue and gate history. Start the candidate on the copy, compare IDs,
   exports, migrations, manifest/window output and both dashboards, then verify
   the previous image can open a stopped copy. Do not rewrite historical data.
2. **Physical interfaces and architectures.** Boot the actual supported ARMv7
   and/or ARM64 target image, verify AP/uplink selection, NAT, DNS, conntrack
   accounting and participant-only header capture. Exercise IPv4/IPv6 where the
   deployment supports them. Confirm normal forwarding with the gate and route
   engine disabled, and visible capture warnings if the interface is unavailable.
3. **Gate safety on the Pi.** Follow the complete
   [Proxy Lab failure and mode matrix](proxy-lab-raspberry-pi.md): flow, strict and
   DNS modes, selected/bypass clients, readiness, caps/watchdogs, slow viewers,
   audit storage pressure, session end, clear, SIGTERM, listener/process failure
   and restart cleanup. Held traffic must fail open and every accepted audit
   loss must remain visible. Include actual dnsmasq INPUT and AP/uplink ordering.
4. **Lifecycle under load.** Clear while DNS, derivation, dirty packet chunks and
   probes are active. Pre-clear records must stay deleted, existing tuples remain
   suppressed, new tuples resume, sessions/catalogue/budgets survive, and held
   gate traffic releases. End/reactivate sessions and restart a demo. Test a
   slow write during shutdown; completion or an explicit incomplete-drain error
   must occur without closing a resource beneath an active writer.
5. **Matched performance and storage.** Use the same workload/configuration on
   baseline and candidate, with five-minute warm-up and 60-minute measurements.
   Follow the [packet activity](flow-activity-raspberry-pi.md),
   [route](live-route-discovery.md) and [lab](proxy-lab-raspberry-pi.md) procedures.
   Record CPU, RSS, database growth, chunk/derived writes, route attempts/spend,
   drops, client latency/throughput and dashboard load/render time. Run rolling
   retention for at least two full windows with routes enabled and disabled;
   retained storage should plateau while ordinary history/catalogue survive.
6. **Both dashboard transports.** Exercise live and recorded playback in the
   dashboard and debug dashboard, normal timeline loading and an older gateway's
   collection/realtime fallback. Seek before/after route confirmations,
   enrichment and invalidation, verify map geography and alternatives, and ensure
   gate queued/verdict phases reconcile without duplicate or missing decisions.

Attach the completed existing-guide tables, image/source identifiers,
configuration, logs and deviations to the release. Passing local checks does not
check off these hardware items; there is no measured Pi performance claim yet.
