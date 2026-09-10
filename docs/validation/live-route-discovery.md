# Live route discovery validation

Use the [implementation guide](../implementation-guides/live-route-discovery.md) for configured probe budgets, deployment and diagnostics. Actual Pi CPU, memory, probe rate, persistence latency and sample-to-screen percentiles remain unmeasured; the targets below are acceptance criteria, not performance guarantees.

## Timing contract

Target visible traffic and route state in under two seconds normally, with a five-second deadline on a healthy gateway and connected dashboard. Show a compatible cached route, newly measured partial evidence or explicit pending/unknown state. Missing route information must not hold back traffic.

Fresh discovery of every hop and its geography cannot be guaranteed. Routers can suppress replies and replying IPs can lack coordinates. A disconnected browser, overloaded gateway or cold burst exceeding worker capacity must expose delayed/pending state.

For immediate worker admission, the proposed cold-route budget is one second for flow discovery, 250 ms for scheduling, three seconds for probing and 500 ms for persistence/delivery/rendering: 4.75 seconds. A cache hit skips probing. Queued destinations still need visible state within the display deadline even when measurement arrives later.

## Automated checks

From the repository root:

```bash
pnpm test
pnpm lint
pnpm build
(cd pocketbase && go test ./...)
(cd pocketbase && go test -race ./routing)
(cd pocketbase && GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...)
(cd pocketbase && GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build ./...)
```

Run the routing suite on Linux with the traceroute executable shipped in the proxy image as well. Parser-only tests cannot establish progressive publication: the real executable/pipe tests must verify output framing, draining on cancellation and TCP/UDP loopback behavior.

`scripts/test-route-coverage-netns.sh /path/to/routing.test` runs the real coverage engine and diagnostic tool in private sender/router/destination namespaces. Build the test binary with `go test -c ./routing` for the container architecture. Run in a disposable Linux container with `ip`, `iptables`, `traceroute`, `scamper`, `tcpdump` and namespace/raw-socket capabilities. Use `--network none`; the test creates its own veth links and needs no Internet access. It cleans up its namespaces and changes no host firewall rules.

Retain deterministic integration coverage for:

1. **Shared reuse:** a new session receives compatible cached evidence with its original age; simultaneous callers share one attempt. A failed refresh neither erases useful evidence nor renews its age.
2. **Priority and bounds:** a cold burst of 79 destinations followed by a high-volume stream promotes that stream ahead of low-volume backlog. Assert worker/output/queue limits, fair starts and bounded memory. Do not expect all cold probes within five seconds.
3. **Progressive output:** publish partial snapshots before exit; handle split reads, missing final newline, timeout, IPv6 and unreachable markers without discarding received evidence.
4. **Background repair:** a repair can improve coverage while foreground work proceeds or preempts it. Different attempts and alternate methods remain separate paths.
5. **Temporal correctness:** seeking before a reply, location update or cache binding excludes later evidence. Check protocol/port compatibility, expiry, network changes, pause/resume, reset/restart, clear and cache-retention boundaries. Results must stay attached to the correct session.
6. **Delivery and history:** recover dropped/out-of-order route and activity events through bounded reconciliation. Independently paginate route history, including a range's preceding revision and routes for closed flows. Long live recordings must not retain every revision in overview state.
7. **Map projection:** directional bursts traverse all displayed segments with continuous phase. Gaps, co-located hops, missing geography and absent activity stay distinguishable. Unknown destination geography must not hide a located route prefix. Incoming traffic uses the labeled gateway-route approximation; it is not a measured return path.

## Raspberry Pi workload

Deploy a candidate build and start a fresh session. Repeat SVT video, YouTube and Spotify with cold and warm route caches. Start another session to verify reuse; a CDN choosing another IP requires a new measurement.

Measure from gateway observation time to visible browser state, including persistence and delivery. Capture the route status API alongside browser timings. Compare representative paths with a lower-concurrency probe to determine whether the fast profile sacrifices replies. Verify the retired scheduler does not run alongside the routing module.

| Pi / OS / commit / configuration | Cold cache | Warm cache |
| --- | --- | --- |
| First traffic/state latency p50 / p95 / maximum | | |
| First useful hop / destination-reached latency | | |
| Directional sample-to-screen delay | | |
| Recent-byte route coverage | | |
| Reached destinations / replying hops / located hops | | |
| Cache hits / stale hits / attempts per key | | |
| Queue age / deferred demand / worker utilization | | |
| Probe packets per second, including responses and resets | | |
| Persistence latency / failures | | |
| CPU / memory / route-history payload and cache size | | |

Keep cache freshness, destination reachability, responding hops and geographic coverage separate. The status API's measured-byte coverage requires at least one usable responding hop; it does not imply a complete or located route.

Attach completed measurements and deadline misses to the release or issue. Tune worker count and pacing from Pi evidence; automatic rate adaptation remains follow-up work.

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
