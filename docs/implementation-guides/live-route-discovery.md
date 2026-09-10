# Live route discovery

Route discovery is implemented; real Pi workload acceptance remains pending. The [validation procedure](../validation/live-route-discovery.md) defines the timing contract and acceptance scenarios. Timings below are configured budgets, not measured Internet performance.

## Evidence boundaries

Routes are gateway measurements, not proof of the application path; see [ADR 0001](../adr/0001-metadata-gateway-not-transparent-tls-proxy.md). Forwarding and the optional controls in [ADR 0002](../adr/0002-opt-in-nfqueue-flow-admission.md) remain independent of discovery.

Never splice hops from different destinations, methods or attempts into a supposedly measured path. Destination reached, hop replies and geographic coverage are separate facts. Preserve logical TTL positions even when geographic rendering skips unlocated hops. Coordinates describe approximate areas; retain their source/version and accuracy radius.

Route identity uses network context and the destination IP/protocol/port binding, not a domain, provider, city or subnet. Measurement time and session availability time must remain distinct: a cache hit is old evidence made available to the new session now. Playback must not reveal future replies, location updates or invalidations.

## Runtime

`pocketbase/routing` owns discovery behind `Observe`, `Status`, and `Reset`. Conntrack sends committed cumulative flow counters every second. Repeated notifications coalesce; existing connections establish a counter baseline at session startup. Unchanged sockets retain a two-second database heartbeat.

The scheduler aggregates ten seconds of byte deltas by destination IP, protocol and port. Destinations carrying 90% of recent bytes receive priority, missing evidence precedes refreshes within that group, and every fourth start serves the oldest eligible destination. Four workers run by default, with 1,024 pending keys and bounded intake. All destinations receive an initial queued or cached session state without waiting for a probe worker.

Fast probes use numeric Linux traceroute output, one query per TTL, up to 32 TTLs, eight outstanding probes, a 500 ms reply wait, 40 ms pacing, and a three-second process deadline. Output is capped at 128 KiB and parsed incrementally. Changed hop snapshots publish at most every 200 ms, with an immediate terminal snapshot. A deadline preserves responses already received. TCP uses the observed port; UDP uses fixed-port UDP.

One background coverage pass may run at a time, within the same worker budget. It starts with the observed protocol, then rotates through ICMP Paris and the remaining TCP/UDP Paris method if the route still has gaps. Scamper keeps a stable source identifier and destination port within each attempt, paces at five probes per second, and retries unanswered TTLs up to three times. UDP/ICMP allow two outstanding TTLs; TCP uses one because the packaged Bookworm engine failed to recognize terminal TCP replies with parallel TTLs in the network test. Each pass has a 45-second total deadline (`ROUTE_QUALITY_SECONDS`, 15–90 seconds) and publishes completed groups of four TTLs. Cancellation retains completed groups and explicitly marks the unprobed tail. Fast discovery stays independent of this longer coverage budget.

Coverage work becomes eligible five seconds after initial discovery for destinations carrying the foreground share of traffic. Methods have a 15-second cooldown; a three-method round has a ten-minute cooldown. A cancelled pass retains its method for retry. New foreground probes can preempt coverage when workers are full. Missing executables or denied raw-socket permissions pause the coverage engine for one minute while fast discovery continues.

Reached routes are fresh for ten minutes and usable as explicitly cached evidence for up to an hour. Partial paths expire after one minute. Failed attempts back off for 15 seconds, one minute, then five minutes, with bounded jitter. Failure or a sparser refresh cannot erase stronger unexpired evidence or renew its age. The cache retains the best path and separate evidence per method; hops from different attempts are never combined. Cache keys include the local network fingerprint, destination binding, and probe-policy version; each observation also records its actual probe method. Changes in interfaces, routes or policy rules invalidate current session bindings. Unknown network contexts are isolated per process startup.

Local GeoIP lookups have a bounded per-process positive/negative cache, tied to the loaded database version. Snapshot coordinates and accuracy radii are immutable. Destination/PTR enrichment remains separate; PTR lookups have a 500 ms timeout. There is no DNS dependency in the probe path.

## Data and playback

- `route_observations`: immutable attempt snapshots.
- `route_cache`: persistent best/last and per-method evidence, expiry, retry and coverage state; up to 10,000 keys and 24-hour unused retention.
- `routes`: immutable session revisions with actual availability time, original measurement time, status, provenance and compatible hop fields. `probe_details` describes the displayed and latest attempts; `alternate_routes` contains separate method results.

Coverage hop records retain individual responder addresses, probe IDs, RTTs and terminal reply types. Different responders at one TTL remain explicit; map connections through that position are marked uncertain. Unusable wrapped RTTs from the packaged engine retain their original reported value but do not become displayed latency or future reply timestamps. Both inspectors show responding and located hop counts, and expandable alternate paths.

Migrations run automatically. Existing `routes` records remain readable; legacy availability is their completion time. The older `traceroutes` collection is untouched. Clear-observations includes the new collections. Session-referenced evidence survives global cache eviction.

Session windows page route history independently of flows. Overview returns the latest revision per binding; a detail range includes its preceding revision plus changes within the range. The shared browser store retains latest pointers and revisions owned by bounded detail pages. `routeForFlowAt` applies protocol/port matching, availability, expiry and network invalidation at the playback cursor.

Both inspectors use that selector. The map can show located hops before either probe completion or destination enrichment. Unlocated and unanswered spans remain gaps. Incoming and outgoing samples drive separate lanes along the same gateway-measured approximation. Rate changes apply along the whole path immediately; decorative motion adds no four-second delay. The return path is not independently measured.

Realtime remains the primary delivery channel. Two-second reconciliation repairs overview and the open activity/route tail. Tail requests batch at most 200 selected flows and rotate through at most four batches per cycle. Very large working sets or a slow gateway can exceed the target recovery time.

## Rebuild and test on the Pi

After updating the Pi checkout, rebuild the server and whichever dashboards it hosts:

```bash
docker compose --profile debug up -d --build proxy dashboard debug-dashboard
docker compose logs -f proxy
```

If the dashboards run locally, rebuild only `proxy` on the Pi and reload the local dashboards. Existing recordings are preserved by the migration. Start a new session for progressive route evidence; old recordings cannot acquire historical hop timing retroactively.

1. Open an SVT video, then YouTube and Spotify. Check how quickly a track appears, its first useful hop, and the reached/partial state.
2. Start another session and revisit those services. Matching IP/protocol/port bindings should show cached evidence with its original age. CDNs may choose different IPs, which require new measurements.
3. In Traffic → utilities, inspect Route discovery: running/waiting probes, cache hits, recent-byte coverage, oldest wait, failed attempts and deferred demand.
4. Compare with a lower-concurrency run if there are many gaps. `ROUTE_WORKERS=2 docker compose up -d proxy` recreates the proxy with two workers. The default is four; supported values are 1–8. `CONNTRACK_SAMPLE_MS` defaults to 1000, with a 250–5000 ms range.

Read diagnostics directly with:

```bash
curl http://localhost:8090/api/infrareveal/routes/status
```

The API's measured-byte coverage means recent bytes have at least one usable responding hop. Reached-byte coverage requires a terminal destination reply; located-byte coverage requires at least one located hop. `hop_coverage` is the recent-byte-weighted fraction of probed TTL positions that answered. These metrics do not imply that all routers are geographically located. Counters are collector totals; route states and measurement age remain available per connection. Periodic logs report queue depth, active probes, starts, cache hits, failures and oldest waiting age.

### Compare probes with returning ICMP

The image includes `route-diagnose`, independent of the running server. Choose an IP and port from a recorded connection and the actual uplink interface:

```bash
docker compose exec -T proxy route-diagnose \
  --target 109.105.98.205 --port 443 --interface eth0 \
  --seconds 45 --hops 20 > route-comparison.jsonl
```

This runs four bounded comparisons: the previous one-query TCP profile, paced TCP, paced ICMP, and paced fixed-port UDP. It records command output, parsed hops, routing/firewall context and tcpdump summaries of returning ICMP headers. It does not modify sessions, routes or firewall rules. The full comparison can take about three minutes; `--seconds` is a per-profile deadline. Header capture requires raw-socket permission and firewall inspection requires network administration permission, already available in the proxy container.

If a reply appears in capture but not traceroute, investigate local filtering or probe matching. If all methods stop at the same hop and later ICMP never reaches the interface, local parsing cannot recover those missing replies; investigate the upstream network. A destination replying while intermediate TTLs do not is valid partial path evidence.

## Validation

Use the [route validation procedure](../validation/live-route-discovery.md) for automated checks, executable/pipe tests, replay and cache scenarios, and cold/warm Pi measurements. Existing recordings are useful for compatibility smoke checks; progressive timing requires recordings from the updated gateway.

## Remaining validation and refinements

Actual Pi CPU, memory, probe packet rate, persistence latency and sample-to-screen percentiles have not yet been measured. Worker count and pacing are fixed limits; automatic rate adaptation remains follow-up tuning. The initial implementation changes route geometry immediately while keeping animation phase continuous; a brief geometry crossfade remains a visual refinement. PTR work is bounded but still uses the existing serial enrichment loop.

Useful route state is designed to appear within five seconds on a healthy connected setup. A cold probe queued behind other foreground work can take longer, and routers may never return every hop. Pending work and partial evidence remain visible so those cases can be measured during the first Pi sessions.

## Protocol and geolocation references

- [RFC 1812: ICMP rate limiting](https://datatracker.ietf.org/doc/html/rfc1812#section-4.3.2.8) and [Time Exceeded](https://datatracker.ietf.org/doc/html/rfc1812#section-5.2.7.3): hop replies can be suppressed or rate-limited.
- [Linux traceroute manual](https://man7.org/linux/man-pages/man8/traceroute.8.html): probe methods, pacing, concurrency and timeout controls.
- [Scamper's Bookworm manual](https://manpages.debian.org/bookworm/scamper/scamper.1.en.html): Paris methods, retries, stable identifiers and JSON output. The namespace test checks the exact packaged executable.
- [Traceroute source](https://sources.debian.org/src/traceroute/1%3A2.1.0-2%2Bdeb11u1/traceroute/traceroute.c): reference for output framing; test the exact executable shipped in the proxy image.
- [MaxMind City database documentation](https://dev.maxmind.com/geoip/docs/databases/city-and-country/?lang=en): location provenance and accuracy radius.
