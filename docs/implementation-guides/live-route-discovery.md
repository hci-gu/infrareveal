# Selective route discovery

Routing collects a few useful gateway-to-destination approximations from captured traffic. The map and activity blocks work when no intermediate path is visible. The storage contract is [ADR 0003](../adr/0003-map-activity-storage.md); historical engine measurements are in [validation](../validation/live-route-discovery.md).

## Admission and stopping

Committed traffic supplies positive wire-byte deltas for an observed numeric IP/protocol/port and network epoch. No persisted flow or conntrack counter is required. A binding qualifies automatically after 1 MiB within 30 seconds, or three positive seconds spanning at least ten seconds. The coordinator ranks qualified demand by recent bytes, prioritizing an unfinished method comparison. Pending bindings and intake are bounded; queue eviction never refunds an admitted attempt.

Defaults are 20 automatic targets, 40 automatic attempts and ten manual attempts per recorded session. Continuous sessions renew those allowances in hourly scopes relative to their start time. A separate rolling limit allows 40 total admissions per stable network and address family per hour, across sessions and restarts. Deleting or clearing a session cannot reset this network limit.

One physical worker holds its lease through process cancellation, pipe drain, enrichment and pacing. Scamper is pinned to Debian Bookworm `20211212-1.1`. A logical task uses five probes/second, two queries per TTL and a 45-second deadline. The default task fits 20 TTLs/40 probes into that deadline, reserving five seconds for startup and completion; the absolute ceiling is 32 TTLs/64 probes. The remaining tail is explicitly unprobed. Engine control traffic is distinct from measurement probes.

TCP uses the observed destination port; IPv4 UDP uses UDP Paris to that port. Either may make one ICMP Paris alternate attempt. The pinned engine failed IPv6 UDP reply correlation in qualification, so IPv6 UDP bindings use only the qualified ICMP Paris approximation. A completed useful result ends automatic discovery for that binding and scope. Otherwise the remaining method stays eligible after traffic becomes idle. No third automatic method is scheduled.

A `probe_runs` reservation commits before each process launch. Failed, cancelled and interrupted attempts remain charged. The ledger also stores the selected synthetic source port, preserving tuple separation across restart and session changes. These are gateway probes, not copies of the application's source tuple; different attempts never have their hops stitched together.

An unsuccessful method suppresses that same network/binding/method for 30 minutes across sessions. Five distinct IPs completing their available methods without useful evidence pause automatic discovery for 30 minutes; an unsuccessful trial after the pause closes it again. Capability failures pause the network/family for five minutes. Losing the network fingerprint suspends admission until it can be established again.

`POST /api/infrareveal/routes/measure` with `{"chunk_id":"TRAFFIC_CHUNK_ID"}` requests one manual attempt against traffic observed in the active session and network epoch. Manual requests have their own ten-attempt allowance and still obey network rate, capability and storage limits. There is no extra-budget API.

## Evidence and retention

A useful path contains a public intermediate responder beyond established access context. An initial responding segment followed by a silent span and possibly the destination is access-only, so it permits the bounded alternate. Geography does not affect acceptance. Access consensus requires matching leading TTL/address positions from three distinct destination IPs; its bounded inputs are reconstructed from recent admissions.

Only completed useful measurements produce paths. Silent, endpoint-only, access-only and status-only outcomes stay on their attempt rows. Cancellation never publishes a useful path. Queue and progress updates remain transient.

| Collection | Stored information and bounds |
| --- | --- |
| `route_evidence` | Self-contained immutable path publications and typed network invalidations. At most one terminal path and one meaningful enrichment revision per run; at most 100 path publications and 16 MiB of charged evidence per session. Each path is at most 64 KiB. |
| `probe_runs` | One reservation/outcome per actual method attempt: scope, binding, timing, method, source port, outcome, suppression deadlines and bounded access-prefix evidence. Optional probe details are capped at 16 KiB. |

There is no permanent cross-session route cache, observation copy, event stream, current-outcome table or mutable budget-state document. A session reuses its own valid paths in the same network epoch. A new session may measure the destination again under the shared network limits. The status endpoint derives spending and latest outcomes from admissions and overlays the in-memory queue.

Freshness is ten minutes and validity one hour from the original measurement. Enrichment cannot extend either, change the measured topology, replace a newer measurement, or resurrect cleared/expired evidence. Measurement and availability times are separate numeric epoch milliseconds. Network changes publish an invalidation for the old epoch atomically with the new session epoch. An unchanged fingerprint across restart keeps the committed epoch; capture epochs are independent.

Replay selects the newest available publication for the exact epoch/IP/protocol/port at the cursor, then applies expiry and invalidation. It never falls back to an older path after the newest one expires. Window reads include the necessary pre-window path anchors and invalidations and report overflow instead of silently dropping evidence. Traffic retention removes unreferenced paths while keeping anchors for retained traffic.

An open recording keeps its lifetime quota rows. Other rows survive a 24-hour network-learning horizon and any unexpired cooldown or pause, including after session deletion. Closed recordings retain self-contained path evidence without depending on those ledger rows. Clearing observations removes route evidence while preserving spending. The byte allowance counts serialized evidence plus bounded overhead, not physical SQLite pages, indexes or WAL.

## Topology and optional diagnostics

The engine's structured output arrives at completion. Unknown, unprobed and silent tails remain distinct; interrupted output cannot reconstruct replies the executable never flushed. Raw stdout/stderr is capped at 128 KiB and is never stored automatically. With full diagnostics enabled, bounded decoded probe details are included on `probe_runs`; dropping those optional details does not block terminal accounting or useful paths.

Private, CGN, loopback, link-local, documentation and other special-use addresses remain unlocated topology nodes. Public responders can receive GeoIP and ASN/PTR evidence from bounded caches. `ROUTE_ASN_DB` optionally supplies local origin-AS/prefix/organization data. Origin ASN does not establish router ownership; PTR and geography retain their sources. No airport-token guessing or hostname re-resolution is used for probing.

The map connects located interfaces in TTL order with approximate segments, retaining unlocated responders and collapsed gaps in the topology details. Multiple responders indicate ambiguity. A destination-only connection has an unknown intermediate path. Return traffic uses the gateway approximation; its return route is unmeasured. RTT differences are not link latency.

## Configuration and audit

`ROUTE_ENGINE=scamper|off` controls automatic/manual collection. `ROUTE_MAX_TARGETS`, `ROUTE_MAX_ATTEMPTS`, `ROUTE_HOURLY_ATTEMPTS`, `ROUTE_MAX_SNAPSHOTS` and `ROUTE_MAX_BYTES` configure the limits above. The 100-publication and 16 MiB ceilings cannot be raised through environment settings. Disabling routing leaves ordinary capture and forwarding running.

```bash
curl http://localhost:8090/api/infrareveal/routes/status
python3 scripts/audit-routes.py /tmp/recording-copy.db --session SESSION_ID > audit.json
```

The audit is read-only. It reports both collections, publications versus distinct bindings/attempts, outcome counts, structural violations, retained deleted-session charges, serialized evidence and physical database allocation. It expects the current schema and provides no compaction or old-recording adapter. This rewrite requires a fresh application database.

## Explicit diagnostics

```bash
docker compose exec -T proxy route-diagnose --target NUMERIC_IP --port 443 --interface eth0 --seconds 45 --hops 20 > route-comparison.jsonl
```

The separate diagnostic compares four traceroute profiles and three Scamper methods sequentially. Each gets the requested deadline; this explicit operation is outside automatic collection. It writes no database or firewall records and caps captured headers/output. It reports capture drops, decode errors, candidate responder mismatches and engine output. IPv6 extension headers require tuple comparison of candidate ICMP headers; capture presence alone does not prove engine matching. Remove the artifact after analysis; normal collection does not retain it.

The Linux namespace fixture exercises the shipped engine without Internet access. Physical gateway measurements remain necessary before claiming improved Internet visibility, CPU/RSS, packet rate or latency. Cross-builds and controlled fixtures establish semantics and bounds, not responsiveness of an uplink.
