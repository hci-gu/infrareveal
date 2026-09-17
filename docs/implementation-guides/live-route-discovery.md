# Selective route discovery

The collector seeks a few useful gateway-to-destination approximations. Ten useful paths are preferable to thousands of empty measurements. `routes` now means accepted useful path evidence; traffic and endpoints remain visible without a route. See [the checklist](../../implementation-plan.md) and [validation](../validation/live-route-discovery.md).

## Admission and stopping

Conntrack supplies observed numeric IP/protocol/port bindings and committed byte counters. Over a 30-second window, automatic candidates must transfer at least 1 MiB or produce three positive samples spanning ten seconds. Only the ten highest-volume candidates compete for admission. The queue is bounded at 256 bindings; intake and flow-counter memory are bounded separately.

Defaults: 20 automatic targets/session; one primary plus one ICMP Paris alternate at most; 40 automatic attempts/session and 40 total admissions/network/family/rolling hour; ten manual attempts/session. One physical worker lease includes cancellation and pipe drain. Scamper is pinned to Debian Bookworm `20211212-1.1`; one logical task uses five probes/second, 32 TTLs, two queries per TTL (64 measurement probes maximum) and a 45-second deadline. Engine control traffic is distinct from measurement probes.

TCP uses the observed destination port; IPv4 UDP uses UDP Paris to that port. The pinned engine failed IPv6 UDP reply correlation in qualification, so IPv6 UDP bindings use one ICMP Paris approximation; the adapter refuses the unqualified UDPv6 profile. These are synthetic gateway probes, not copies of the application's source tuple. Methods and attempts never have their hops stitched together. The legacy engine is paced at five probes/second, one query/TTL, under the same scheduler/storage limits.

Allowances are charged transactionally before process launch, including failed/cancelled starts. They survive restart, queue eviction, cache expiration, clearing observations and session changes where applicable. A useful result ends automatic work for its binding. Unsuccessful methods are suppressed for 30 minutes across sessions. After five distinct IPs complete both methods without useful new evidence, automatic discovery pauses for 30 minutes; the next eligible trial must add evidence to reopen discovery. Capability failures pause the affected network/family for five minutes. An unavailable network fingerprint pauses admission instead of granting a fresh allowance.

“Measure this destination” requests one bounded manual attempt for an observed active-session flow. It retains global rate, hour, capability and storage limits. Traffic utilities can explicitly add 20 targets and 40 attempts to a session, up to 100 automatic targets total; this never increases the 100-snapshot or 16 MiB ceilings.

## Evidence and storage

A useful path has a public intermediate interface beyond established access context, or a destination response plus an intermediate interface. Geography is irrelevant to acceptance. An access prefix requires matching leading TTL/address positions from three distinct destination IPs, with supporting measurement IDs and timestamps. Provisional public-prefix observations before consensus remain historically intact.

Silent, endpoint-only, local/access-only and status-only results produce no route snapshots. One bounded outcome per admitted binding explains the latest result. Queue/progress ticks stay in memory. Canonical path fingerprints include binding, network/source, method, responder sets at each TTL and terminal evidence; RTT jitter, timestamps and timeout-only tail growth add no geometry.

| Collection | Bound / meaning |
| --- | --- |
| `routes` v2 | Immutable useful paths; 100/session; two/attempt maximum, first useful and materially different final |
| `route_observations` | One normalized bundle per accepted snapshot; 64 KiB/bundle |
| `route_outcomes` | One current summary/binding; 4 KiB each |
| `route_budget_state` | Finite spending maps, rolling starts, suppression and source context |
| `route_cache` | Useful geometry only; 1,000 entries; 24-hour unused eviction |
| `route_evidence_updates` | Confirmation/enrichment up to 100/session, 16 KiB/event; network invalidations separately authoritative |

The 16 MiB session payload allowance conservatively charges geometry, evidence bundles, cache copies, summaries, updates and reference overhead. It measures serialized evidence, not SQLite pages/indexes/WAL. Minimal control/budget records stay outside that allowance. Admission leaves capacity for both useful milestones. Deduplication and terminal idempotency run in the same transaction as spending updates.

The packaged whole-task engine writes structured results at completion. Valid output returned with cancellation is retained; an interrupted task with no final JSON exposes unknown probe extent. It cannot reconstruct replies that the executable never flushed. Raw stdout/stderr is capped at 128 KiB and never stored automatically. Silent ranges are compacted; unprobed and unknown tails remain distinct.

Useful evidence survives failed manual measurements, global cache eviction and session closure. Freshness is ten minutes, validity one hour. Expiry changes display eligibility without restarting automatic collection. Network changes invalidate evidence via context events, including changes detected across restart. Session deletion cascades new session records; clear-observations clears evidence but preserves spent limits.

## Enrichment and display

A shared address policy excludes private, CGN, loopback, link-local, documentation and other special-use addresses from public inference. Such responders remain unlocated topology nodes. Public responders use bounded GeoIP and ASN/PTR caches. `ROUTE_ASN_DB` optionally supplies local origin-AS/prefix/organization data; origin ASN is not asserted to be router ownership. PTR and GeoIP remain separate evidence with provenance. No airport-token guessing or hostname re-resolution is used for probing.

Both dashboards use exact session/IP/protocol/port matching and `routeForFlowAt`. Recorded projections apply confirmation, enrichment and invalidation only after each event's availability time. Collection fallbacks load those events too; realtime reconciliation cannot erase already loaded events. Current outcome/status summaries are not inserted into recorded history.

The map connects located interfaces in TTL order with approximate, uncertain segments. A topology strip retains unlocated responders and collapsed gaps. Endpoint-only connections explicitly say that the intermediate route is unknown and do not count as useful paths. Multiple responders mean ambiguity, not a confirmed router graph. Return traffic is associated with the gateway approximation; its return path is unmeasured. RTT differences are not link latency.

## Configuration and operations

`ROUTE_ENGINE=v2|legacy|off` selects the engine. `ROUTE_MAX_TARGETS`, `ROUTE_MAX_ATTEMPTS`, `ROUTE_HOURLY_ATTEMPTS`, `ROUTE_MAX_SNAPSHOTS`, and `ROUTE_MAX_BYTES` configure the documented limits. Hard snapshot and byte ceilings cannot be raised through environment configuration. `CLIENT_CIDRS` accepts comma-separated IPv4/IPv6 CIDRs; legacy `CLIENT_IP_PREFIX=10.0.0.` remains compatible. Set `GATEWAY_IP` to both gateway addresses for dual stack. These settings do not provision IPv6 forwarding on the gateway.

```bash
curl http://localhost:8090/api/infrareveal/routes/status
python3 scripts/audit-routes.py pocketbase/pb_data/data.db --session SESSION_ID > audit.json
```

The status endpoint reports useful paths/bindings, attempts, no-gain results, stored bytes, remaining allowances and skip reasons. Recent-byte coverage requires useful accepted evidence. Collection status uses one shared two-second browser poll.

Audit is read-only by default and includes routes, observations, cache, operational collections, distinct bindings/attempts/fingerprints and database allocation. Legacy useful candidates are provisional because old records lack access consensus. Optional compaction removes only rows identical in all evidence, availability, validity, provenance and observation fields. It preserves every true temporal transition:

```bash
# Offline COPY only. Creates a backup before deleting exact duplicates.
python3 scripts/audit-routes.py /tmp/recording-copy.db --compact --backup /tmp/before-compaction.db
```

No existing recording is automatically deleted or compacted. Additive migrations keep legacy `missing`/`no_reply`/`complete` records readable. New policy/cache keys cannot inherit old retry loops. Selecting `legacy` retains all new waste controls; selecting `off` leaves observation and forwarding running.

## Explicit diagnostics

```bash
docker compose exec -T proxy route-diagnose --target NUMERIC_IP --port 443 --interface eth0 --seconds 45 --hops 20 > route-comparison.jsonl
```

Seven sequential comparisons cover four legacy traceroute profiles and the three shipped Scamper methods. Each gets the requested deadline; this is a manual diagnostic outside automatic collection. It writes no database/firewall records, caps captured header/output data, and reports capture drops, decode errors, candidate responder match failures and engine output. Capture includes outgoing probes, candidate ICMP errors and terminal TCP/UDP headers. IPv6 extension headers prevent simple fixed-offset quote filtering, so those candidate headers require tuple comparison; capture presence alone is not proof of engine matching. Delete the diagnostic artifact after analysis; the normal collector never retains it.

Rebuild with `docker compose --profile debug up -d --build proxy dashboard debug-dashboard`. Perform the Pi acceptance procedure before claiming Internet visibility, CPU/RSS, packet-rate or latency improvements. Local controlled fixtures establish bounds and semantics, not responsiveness of the affected uplink.
