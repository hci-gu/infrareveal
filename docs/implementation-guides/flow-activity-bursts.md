# Captured traffic and activity blocks

Captured traffic is the source of map volume and temporal service activity. The core model stores aggregate samples directly; no stored connection or successful conntrack match is required. See [ADR 0003](../adr/0003-map-activity-storage.md) for the seven-collection contract.

## Observation and classification

The Linux collector uses an `AF_PACKET` socket on `PACKET_ACTIVITY_IFACE`, defaulting to the client-facing `AP_IFACE`. This preserves client/destination identity before and after NAT. Capture runs independently of forwarding; capture failure is shown as missing coverage.

A BPF filter retains a bounded 256-byte header prefix. `PACKET_AUXDATA` supplies the original wire length through `tpacket_auxdata.tp_len`; the BPF-truncated length must not replace that value. Missing or malformed lengths are capture errors. The packet parser extracts time, directional wire/payload byte counts, packet counts and the normalized client/destination tuple. It discards the prefix after parsing and never persists payload contents. QUIC remains opaque UDP traffic.

The observation scope excludes local infrastructure and gateway-generated traffic. In-scope packets aggregate immediately, including short connections missed by conntrack. DNS and conntrack contribute bounded in-memory classification and connection-generation evidence. They never contribute a second set of byte totals. Tuple reuse, client lease changes and identity-cache eviction invalidate uncertain attribution; unresolved traffic remains an independent destination.

The current session pins its classification and grouping policy. Labels may be corrected during a ten-second mutable tail. A correction reallocates captured contributions atomically rather than copying bytes. Persisted generation checks reject older flushes. Restart seals the old tail and begins a new capture epoch; an unknown sealed sample remains unknown. This is retrospective classification within the bounded tail, not a historical reconstruction of exactly what the system knew at every instant.

## Aggregate samples

Each `traffic_chunks` record groups one session, capture epoch, client scope, service/independent endpoint, immutable destination version, protocol, destination port, network epoch and chunk start (five seconds by default). Client source ports and flow IDs are absent from core storage. Several connections can contribute to one chunk; one connection can contribute to many chunks and activity blocks.

Sparse 50 ms samples have this fixed tuple shape:

```text
[offset_ms, wire_sent, wire_received, payload_sent, payload_received, packets_sent, packets_received]
```

Wire bytes are the accounting source. Payload counts identify transfer-active bins; TCP ACK-only packets contribute wire and packet counts without extending activity blocks. Empty sample buckets indicate silence only where `capture_intervals` establishes complete coverage. Coverage advances after successful persistence and is recorded even when no packets arrive. Queue loss, capture failures and restart gaps remain visible independently of classification.

Open chunks flush approximately every 400 ms. Five-second chunk size does not imply five-second publication delay. Clients replace revised chunks/windows instead of adding new cumulative totals to old ones.

| Setting | Default | Meaning |
| --- | --- | --- |
| `PACKET_ACTIVITY_ENABLED` | `true` | Passive header capture |
| `PACKET_ACTIVITY_IFACE` | `AP_IFACE` | Client-facing interface |
| `TRAFFIC_BUCKET_MS` | `50` | 20–1000 ms, aligned to the chunk size |
| `TRAFFIC_CHUNK_MS` | `5000` | 1000–10000 ms in whole seconds, divisible by the bucket size |
| `TRAFFIC_FLUSH_MS` | `400` | 100–2000 ms persistence interval |
| `TRAFFIC_CORRECTION_MS` | `10000` | 0–30000 ms mutable attribution tail |
| `ACTIVITY_QUIET_GAP_MS` | `45000` | 1000–300000 ms gap between activity blocks |
| `TRAFFIC_MAX_PENDING_CHUNKS` | `4096` | 128–16384 pending contribution entries |
| `PACKET_ACTIVITY_EVENT_QUEUE` | `8192` | 256–131072 parsed metadata events |
| `CONNTRACK_SAMPLE_MS` | `1000` | 250–5000 ms identity checks; never an accounting source |

Sample/correction/grouping settings are pinned in the session policy. Retention belongs to the session; there is no separate flow-activity retention store.

## Activity blocks and retention

`activity_blocks` projects captured payload activity by client and service. The projector unions overlapping active bins, splits after the configured quiet gap or unavailable capture, and keeps each block's observed span separate from its active duration. Several destinations may contribute to one service block. Shared destination IPs do not merge unrelated services or clients.

A block is inferred service activity, not measured browser attention, an HTTP request or a page visit. Background transfers can contribute. A connection left open across a long quiet gap produces separate blocks. ACK-only traffic and traffic outside blocks remain in map totals; block sums need not equal all captured traffic.

Continuous-session cleanup clips retained samples, recomputes block totals and keeps the identity/original-start anchor of a crossing block. It removes destination versions only when no retained chunk references them. Route anchors remain available for retained exact bindings. Expanding retention cannot recover deleted data; SQLite may keep allocated pages for reuse.

`flow_diagnostics`, `dns_queries` and `gate_events` are optional diagnostic stores. The default connection inspector is replaced by activity/service evidence. Turning on diagnostics does not change the source of map or block totals.

## Ownership and loading

| Area | Code |
| --- | --- |
| Capture lifecycle and persistence ordering | `pocketbase/observer/runtime.go` |
| Header parsing and original wire length | `pocketbase/observer/packet_parser.go`, `packet_activity_linux.go` |
| Bounded identity, corrections and aggregation | `pocketbase/observer/aggregate.go`, `classification.go` |
| Typed persistence and coverage | `pocketbase/observer/storage.go`, `pocketbase/data` |
| Pure block projection and retention | `pocketbase/observer/blocks.go`, `retention.go` |
| Manifest, bounded map windows, block pages | `pocketbase/timeline`, `pocketbase/gateway/timeline.go` |
| Shared browser contract and runtime | `packages/session-state/src/data`, `runtime.ts` |
| Map activity and block browsing | `dashboard/src/map`, `debug-dashboard/src/experiments/session-playback` |

Both dashboards consume bounded product windows and one coalesced session revision signal. A refresh replaces the relevant window; pagination and overflow remain explicit. Missing capture is shown as missing or partial, never as confirmed idle time. Directional totals and cursor clipping must conserve captured bytes within the sample resolution.

## Verification

Use synthetic metadata or header-only fixtures for IPv4/IPv6, TCP/UDP, VLANs, options, ACK-only packets, fragments, truncation and infrastructure filtering. Preserve regressions for byte conservation, tuple/lease reuse, correction-window expiry, stale flushes, restart sealing, capture gaps, overlapping services, repeated visits, block clipping and database rollback.

The [historical Pi capture procedure](../validation/flow-activity-raspberry-pi.md) contains useful socket and forwarding checks, but its old flow-store/API examples do not apply to this schema. Validate the new build with fresh data, participant traffic, pause/seek, block details and retained-window totals. Measure write rate, database growth, memory and map-window latency on the target hardware; local parser tests cannot establish those results.
