# Selective route discovery validation

Candidate: working tree, 17 September 2026. The [implementation guide](../implementation-guides/live-route-discovery.md) documents current semantics. The older investigation below is retained as historical context, not validation of this rewrite.

## Affected Pi investigation — 17 September, 12:31–12:38 UTC

Read-only inspection of live session `g5el86tarhbn1ny` (`testing`) found six attempts: four automatic and two manual. Three UDP attempts ended at the 45-second deadline without a complete record. The three saved TCP paths all contained `192.168.10.1` at TTL 1, `130.241.190.9` at TTL 2, a silent middle, and the destination at TTL 10 or 11. All six outcomes were primary methods; no alternate completed.

The shipped diagnostic ran on the ARMv7 Pi against observed destination `162.159.130.234:443`, on `eth0`, with a 45-second/profile deadline and 20-hop maximum. It wrote temporary header summaries only; production binaries, session records and firewall rules were unchanged.

| Profile | Responding TTLs | Duration | Result |
| --- | --- | --- | --- |
| Linux traceroute TCP baseline | 1, 2, 10 | 1.2 s | Destination reached |
| Paced TCP | 1, 2, 11 | 25.9 s | Destination reached |
| Paced ICMP | 1, 2, 11 | 25.8 s | Destination reached |
| Paced UDP | 1, 2 | 45.2 s | Deadline; partial text retained |
| Scamper TCP | 1, 2, 11 | 17.0 s | Destination reached |
| Scamper UDP Paris | 1, 2 | 36.8 s | Hop limit; complete structured output |
| Scamper ICMP Paris | 1, 2, 11 | 16.8 s | Destination reached |

Capture reported zero kernel drops in every profile. No remote intermediate responder appeared in capture but disappeared from decoding. The diagnostic's coarse TCP accounting included locally generated resets (`192.168.10.120`) as an unmatched candidate; these are outgoing control packets, not missing router replies. This is a responder-level comparison, not exhaustive packet matching. INPUT and OUTPUT policy were ACCEPT with no listed rules.

A separate ICMP Paris check against observed UDP destination `151.101.3.6` reached it at TTL 9 with only TTLs 1 and 2 answering in between. A broader ICMP capture, without a quoted-target filter, likewise showed only those initial routers and the endpoint, with zero kernel drops. Therefore changing among the tested methods did not expose the remote middle on this uplink. The evidence cannot distinguish upstream filtering from routers declining to answer, or identify exactly where replies are lost.

Three implementation defects were reproduced and corrected locally:

- Initial segment + silent middle + endpoint was accepted as useful and stopped comparison. A regression using the captured route shape now produces zero useful routes and allows the alternate.
- Comparison eligibility incorrectly depended on the recent-activity window after the first attempt. A persisted timed-out primary plus an idle baseline now runs its remaining alternate automatically, and never a third method.
- Two serial one-second waits across 32 TTLs exceeded the 45-second process budget. An actual pinned-engine namespace regression lost its first-hop evidence at 45.04 seconds before the fix; fitting the task to 20 TTLs returned it at 38.48 seconds, with an explicit unprobed tail. Retries, pacing and the wall deadline are unchanged. Deeper destinations can remain unprobed under this budget.

The Go package suite, focused routing race checks, ARMv7 cross-build and ARM64 test-binary build pass for these corrections. The isolated engine matrix rechecks loss recovery, IPv6 fallback, NAT and cancellation. Run the new silent-tail regression with `IR_ROUTE_NETNS_ONLY=silent-budget scripts/test-route-coverage-netns.sh /path/to/routing.test` inside the same disposable Linux fixture.

These corrections address wasted work and false useful-path counts. They do not recover the intermediate routers absent from the actual captures. They have not been deployed to the Pi as part of this investigation. The larger workload/storage and rollback acceptance items below remain outstanding.

## Local results

| Check | Result |
| --- | --- |
| 5,200 silent progress publications | Zero routes, observations, outcomes or budget records created by progress |
| Repeated identical completed useful topology | One route, one observation, one current outcome; finite callback idempotency |
| 1,000 automatic destination admissions | Twenty admitted; eviction/restart cannot restore allowance |
| Five fully silent two-method comparisons | Ten attempts; zero routes; five outcomes; persistent network pause |
| Visibility pause expiry | One no-gain trial closes discovery again |
| Storage | Snapshot limit, conservative byte limit, rejected geometry retaining terminal outcome, transaction deduplication |
| Source changes | Persistent context invalidates previous source after restart; one event/context change |
| Playback | Exact IP/protocol/port; no future confirmation/enrichment; authoritative network epochs; compact gaps |
| Workspace | Frontend tests, lint and production builds pass (existing large-chunk warnings remain) |
| Go | All packages and routing race suite pass; ARMv7 and ARM64 cross-builds pass |
| Audit/compaction | Read-only dry run leaves data untouched; exact duplicates only; different availability retained; SQLite backup retains pre-compaction copy |

The read-only local database audit found **zero route rows** in a 294,912-byte database. It is not the reported 5,200-row recording. That recording's contribution from queue ticks, retries, cached copies and genuinely different measurements remains unmeasured. No recording was compacted or deleted.

## Actual engine qualification

Disposable Debian Bookworm ARM64 container, `scamper=20211212-1.1`, `--network none`, private sender/router/destination namespaces. The fixture changes only its own namespace addresses/firewall rules. The real executable tests establish:

- IPv4 TCP, UDP Paris and ICMP Paris recover a deliberately dropped first-hop response; one-query baseline misses it.
- IPv6 TCP and ICMP Paris reach the endpoint through a responding intermediate interface.
- IPv4 TCP through NAT preserves the gateway source identity and terminal evidence.
- Cancellation without a complete JSON result produces unknown probe extent, not invented `no_reply`/`not_probed` facts.
- All seven diagnostic profiles capture candidate ICMP headers before deliberate INPUT filtering; the clean-input comparison also passes with zero kernel capture drops.
- Production structured results must match the reserved engine sequence, method and TCP/UDP source/destination ports. Negative decoder fixtures reject another attempt/port/method. A persistent scalar prevents immediate synthetic source-port reuse across restart/session changes.

**Qualified exception:** UDP Paris over IPv6 failed in this exact engine/runtime: capture saw outgoing probes and returning ICMPv6 but the JSON contained no matched replies. Datalink receive and error-queue trials did not fix it. Automatic IPv6 UDP bindings therefore use the verified **ICMP Paris approximation**, one method only, within the same budgets. The adapter refuses an explicit unsupported UDPv6 automatic profile. The independent diagnostic retains UDPv6 for investigation. This is an engine qualification limitation, not evidence that the destination or ISP drops traffic.

The executable's [documented trace options](https://manpages.debian.org/bookworm/scamper/scamper.1.en.html#TRACE_OPTIONS) specify per-hop attempts, pacing, flow identifiers and whole-task output. The initial adapter cannot recover unflushed replies from a killed process. The diagnostic reports candidate responder IPs present in capture but absent from decoding; this is not packet-by-packet matching. Dedicated delayed-packet injection, exhaustive matching accounting and the ARMv7 executable matrix remain release qualification work; cross-compilation is not equivalent to those tests.

## Browser checks

The loopback fixture supports `POST /__fixture {"routes":true,"count":8}`. It supplies a fully located path, a reached path with TTL 3–12 unknown, an unlocated useful partial path, shared-access outcome and endpoint-only fallback. No gateway records are written.

Verified the production map's exact connection selection and unlocated path details; the topology strip retains interface addresses and collapses silent positions. Verified recorded Traffic selection: before route availability the inspector showed an unknown intermediate route; at the recording end it showed TTLs 1, 2, 3–12 unknown and 13 with zero located interfaces. Also verified reached-with-gaps and endpoint-only explanations; current collection controls stay out of closed-session playback. Screenshots are under `output/playwright/routes-*.png`. Shared selector tests additionally enforce event availability before/after seeking, including confirmations and enrichment. These screenshots are fixture verification, not measured before/after Pi results.

## Reproduce automated checks

```bash
pnpm test
pnpm lint
pnpm build
(cd pocketbase && go test ./...)
(cd pocketbase && go test -race ./routing)
(cd pocketbase && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...)
(cd pocketbase && GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build ./...)
```

Build the routing test binary for the container architecture and run `scripts/test-route-coverage-netns.sh /path/to/routing.test` inside a disposable Linux container with namespace/raw-socket capabilities and the shipped tools. The script covers IPv4, IPv6, NAT, filtered replies and cancellation; it needs no Internet connection.

## Outstanding physical gateway acceptance

Use the same recorded demand and matching cold/warm-cache Pi sessions for minimal browsing, SVT, YouTube and Spotify. Record build/configuration, duration, targets, attempts, useful bindings/snapshots, outcomes/cache/events, total serialized bytes and physical SQLite growth, measured packets/second including control traffic, CPU/RSS, and browser latency.

1. Audit an export or offline copy of the actual 5,200-row recording. Preserve it; report aggregates, not inferred causes.
2. Require at least 98% fewer newly written routes in the matched reproduction, zero status-only/duplicate routes, and no useful fixture-path loss below budgets. The independent ceilings remain 100 snapshots and 16 MiB.
3. Verify healthy observed-traffic/status visibility within five seconds. Measure useful remote-hop latency separately; no response-time guarantee is made.
4. Confirm restart/session changes/clearing observations cannot replenish limits; collection pauses must leave forwarding and activity observation working.
5. Qualify the actual ARMv7 image if that is the deployment platform; repeat configured dual-stack and delayed-reply cases on the gateway.
6. Exercise rollback with an additive-migrated recording and run the bounded capture diagnostic on the affected uplink. Determine transmission/reception/matching/parsing/display loss only from observed evidence.

No Pi deployment, matched workload, affected-uplink diagnosis or actual-recording compaction was performed in this implementation run.

---

## Coverage implementation checks — 10 September 2026

The isolated Debian Bookworm ARM64 network test used the packaged Linux traceroute and Scamper executables. Its router deliberately dropped the first and then every other Time Exceeded reply, resetting the loss pattern before each profile.

| Profile | Responding TTL positions | Destination reached | Probes |
| --- | --- | --- | --- |
| Previous one-query TCP | 1 of 2 | Yes | 2 |
| Coverage TCP | 2 of 2 | Yes | 3 |
| Coverage UDP Paris | 2 of 2 | Yes | 3 |
| Coverage ICMP Paris | 2 of 2 | Yes | 3 |

The test exposed two engine/capture edge cases before deployment: parallel TCP TTLs in the packaged Scamper failed to recognize terminal TCP replies, and buffered tcpdump output could miss very fast replies at shutdown. TCP coverage now uses one outstanding TTL. Capture uses immediate mode and a short drain. Regression tests also check later segments' absolute TTL numbering, preservation of individual responders, destination Time Exceeded versus terminal replies, wrapped RTT handling, cancellation progress, preemption, cache strength and separate alternate observations.

For diagnosis, a second test dropped returning ICMP in the sender's INPUT chain. All four comparison profiles captured the reply before local filtering while traceroute reported the missing hop. Repeating with no local drop verifies capture for fast successful probes too.

Go package tests and routing race checks pass. Frontend tests cover alternate evidence availability, unchanged cached age and uncertain map connections through multiple responders. Workspace tests, lint and production builds pass. The server and diagnostic tool cross-build for ARMv7, matching the inspected Pi. A temporary browser fixture verified expanded coverage and alternate-route details; it did not write session data. These local tests do not measure Internet coverage or the five-second display target.

### Pi investigation status

The older recorded session contained nine routes: 23 responding TTL positions out of 137 recorded positions, with 13 located positions. Every route answered at the first two hops, followed by gaps until the destination where it answered. Five TCP routes reached their destinations; four UDP routes exhausted their 20-hop limit. These are position counts, not unique routers, and include the unresponsive UDP tail.

SSH inspection found an ARMv7 Raspberry Pi running a host-networked Debian Bookworm proxy container. INPUT and OUTPUT allowed traffic; the lab INPUT chain returned without dropping packets. This rules out an obvious configured local INPUT/OUTPUT drop, but does not establish what happens to returning ICMP upstream.

A temporary diagnostic container was prepared with a 40-minute lifetime and automatic removal; a standalone diagnostic binary was copied to `/tmp`. The user moved to a different network before the actual probe-and-capture comparison ran. The running proxy was not rebuilt or restarted, and session data and firewall rules were not changed. Repeat the documented diagnostic command when Pi access returns; no coverage improvement on that uplink is claimed yet.
