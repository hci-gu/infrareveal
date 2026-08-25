# Implementation Guide: Flow Activity Bursts

## Status

Implemented on 2026-08-25. This document is both the feature contract and the implementation/validation guide. Target-device measurements remain deployment-specific and are recorded using the linked Raspberry Pi validation procedure.

## Goal

Show when bytes actually move inside a long-lived connection without claiming that encrypted traffic bursts are individual HTTP requests.

The timeline should evolve from this:

```text
wm0.cdn.svt.se  ─────────────────────────────────────────
```

to this:

```text
connection      ─────────────────────────────────────────
client → remote     ▪       ▪              ▪
remote → client       ████    ██              ███████
```

The connection bar remains the conntrack lifetime. The inner marks are timestamped transfer activity derived from packet metadata.

## Non-goals

The passive gateway must not claim that a burst is a specific image, script, tracker call, or HTTP request. It cannot reliably recover those boundaries from encrypted HTTP/2, HTTP/3, QUIC, or reused HTTP/1.1 connections.

Phase 1 will not:

- Decrypt TLS.
- Store packet payloads.
- Install client trust certificates.
- Depend on visible SNI.
- Label passive bursts with URLs or resource types.
- Treat inferred request/response pairing as measured browser response time.

Exact resource names and browser timings belong to the optional browser-telemetry extension described later in this guide.

## Current behavior

`pocketbase/observer/conntrack.go` scans conntrack every two seconds. A `flows` record is keyed by protocol, client IP, client source port, destination IP, and destination port.

- `start` is when the observer first sees the conntrack entry.
- `last_seen` is the last scan in which that entry exists.
- Byte and packet fields are cumulative counters overwritten on each scan.
- The observer does not persist earlier counter values or receive an explicit close event.

`dashboard/src/model/sessionModel.ts` turns `start` and `last_seen` into one timeline clip, with a minimum visible duration of 1.5 seconds.

Consequently, the current bar is a sampled connection lifetime. It is not an HTTP request duration, packet lifetime, time to first byte, or resource download duration.

## Architecture decision

Keep conntrack as the authority for flow identity and lifetime. Add a separate, passive packet-metadata observer for fine-grained activity timing.

```text
wlan0 packet headers
        │
        ▼
packet activity observer
  - canonicalize client flow
  - reject infrastructure noise
  - count metadata only
        │
        ▼
50 ms in-memory buckets
        │
        ▼
5 second sparse chunks
        │
        ▼
PocketBase flow_activity_chunks
        │
        ▼
dashboard inbound/outbound overlays
```

Packet processing must never block NAT forwarding. Capture failure should remove burst detail while leaving normal forwarding, conntrack collection, and the dashboard operational.

## Capture source

### Recommended first implementation

Use a Linux `AF_PACKET` socket bound to `AP_IFACE`, which defaults to `wlan0`.

Reasons:

- The container already uses host networking and privileged mode.
- Traffic on the access-point interface is visible before or after NAT in the client-facing tuple needed by the existing flow key.
- `CGO_ENABLED=0` can remain in place; libpcap is not required.
- `golang.org/x/sys/unix` is already available through the Go dependency graph.

Attach a classic BPF filter where practical and cap captured data to the headers required for Ethernet, VLAN, IPv4/IPv6, TCP, and UDP parsing. The implementation may briefly receive a bounded prefix of a packet in memory, but it must discard it immediately after extracting metadata and must never persist payload bytes.

Do not capture on the uplink interface for the first version. NAT changes the tuple there and makes correlation with the client-facing conntrack key harder.

### Packet metadata

For each accepted packet, produce an in-memory event containing:

```go
type PacketActivityEvent struct {
    ObservedAt   time.Time
    FlowKey      string
    Direction    Direction // client_to_remote or remote_to_client
    Protocol     string
    WireBytes    uint32
    PayloadBytes uint32
    TCPFlags     uint16
}
```

Calculate `PayloadBytes` from network and transport header lengths. TCP ACK-only packets should increment packet and wire-byte counters but contribute zero payload bytes. For UDP, use the UDP length minus its header. QUIC remains opaque UDP payload.

Use the existing `ObservationScope` rules after canonicalizing direction. Local, multicast, gateway-originated, DNS, DHCP, NTP, PCP, mDNS, and traceroute traffic must remain excluded.

### Direction and flow-key normalization

Packets in either direction must resolve to the same existing flow key:

```text
protocol | client IP | client source port | remote IP | remote port
```

For client-to-remote packets, the client tuple is the source. For remote-to-client packets on `wlan0`, the client tuple is the destination and the tuple must be reversed before generating the key.

Support IPv4 first if necessary, but isolate parsing behind an interface and include IPv6 fixtures from the beginning so IPv6 can be added without changing persistence or dashboard contracts.

## Aggregation

Do not create one database record per packet or one record per 50 ms bucket. Both approaches create excessive PocketBase writes and realtime events.

### Bucket size

Use 50 ms buckets by default:

```text
PACKET_ACTIVITY_BUCKET_MS=50
```

This gives an 80–120 ms transfer enough resolution to appear across one to three bins. Make the value configurable and validate it within a safe range such as 20–1000 ms.

Each non-empty bucket tracks:

- Client-to-remote wire and payload bytes.
- Remote-to-client wire and payload bytes.
- Client-to-remote and remote-to-client packet counts.
- OR-ed TCP flags by direction.

### Sparse chunks

Group buckets into five-second chunks and store only non-empty buckets:

```text
PACKET_ACTIVITY_CHUNK_SECONDS=5
```

A compact sample can be represented as:

```json
[
  [0,   420, 0,     3, 0],
  [50,  0,   16384, 0, 12],
  [100, 0,   8192,  0, 6]
]
```

The tuple is:

```text
[offset_ms, payload_bytes_out, payload_bytes_in, packets_out, packets_in]
```

Wire-byte totals and TCP flags may be stored as chunk-level fields unless the UI needs per-bucket values. Prefer a versioned JSON object if the tuple needs to grow:

```json
{
  "version": 1,
  "bucket_ms": 50,
  "samples": []
}
```

Batch updates in memory and upsert a chunk at most every 250–500 ms. A slow database must not stall packet capture. Use a bounded channel and expose dropped-event counts in logs.

### Flow resolution

The packet event may arrive before the two-second conntrack sampler creates its `flows` record.

Maintain a bounded pending map keyed by session and flow key:

1. Aggregate activity immediately in memory.
2. Resolve the corresponding `flows` record asynchronously.
3. Hold unresolved chunks for up to five seconds.
4. Persist them once the flow relation exists.
5. Drop them with a diagnostic counter if the flow never becomes an in-scope stored flow.

Do not create `flows` records from packet capture in Phase 1. Conntrack remains the single authority for stored flow identity and noise filtering.

## Persistence model

Add a PocketBase migration for `flow_activity_chunks`:

| Field | Type | Purpose |
|---|---|---|
| `session` | relation, required | Selected observation session |
| `flow` | relation, required | Parent conntrack flow |
| `flow_key` | text, required | Diagnostic and recovery key |
| `chunk_start` | date, required | UTC-aligned chunk start |
| `bucket_ms` | integer, required | Resolution used by this chunk |
| `samples` | JSON, required | Versioned sparse activity samples |
| `wire_bytes_out` | integer | Total client-to-remote wire bytes |
| `wire_bytes_in` | integer | Total remote-to-client wire bytes |
| `payload_bytes_out` | integer | Total client-to-remote transport payload |
| `payload_bytes_in` | integer | Total remote-to-client transport payload |
| `packets_out` | integer | Client-to-remote packets |
| `packets_in` | integer | Remote-to-client packets |
| `updated_at_source` | date | Time of newest incorporated packet |

Add a unique index on `session, flow, chunk_start` and a lookup index on `flow, chunk_start`.

Add the collection before `flows` in `clearObservationCollections` so relations do not prevent clearing. Expose list/view rules consistently with the existing observation collections.

### Retention

Fine-grained activity can grow quickly. Implement retention in the first slice rather than postponing it.

Recommended defaults:

- Preserve full 50 ms chunks for active sessions and recently completed sessions.
- Make retention configurable with `PACKET_ACTIVITY_RETENTION_HOURS`, initially 24 hours.
- Delete expired chunks in bounded batches outside the capture loop.
- Never delete parent flows as part of activity retention.

If longer history is required later, compact old chunks to 500 ms or one-second resolution before deleting fine-grained data.

## Backend modules

Suggested files:

```text
pocketbase/observer/packet_activity.go
pocketbase/observer/packet_parser.go
pocketbase/observer/activity_buckets.go
pocketbase/observer/activity_chunks.go
pocketbase/observer/activity_retention.go
pocketbase/migrations/<timestamp>_flow_activity_chunks.go
```

Keep these concerns separate:

- Packet parsing and direction normalization are pure functions.
- Scope filtering consumes `ObservationScope`.
- Bucketing is independent of PocketBase.
- Chunk persistence is independent of the capture socket.
- Retention never runs in the capture goroutine.

Start the observer from `pocketbase/main.go` after session initialization. Suggested configuration:

```text
PACKET_ACTIVITY_ENABLED=true
PACKET_ACTIVITY_IFACE=wlan0
PACKET_ACTIVITY_BUCKET_MS=50
PACKET_ACTIVITY_CHUNK_SECONDS=5
PACKET_ACTIVITY_RETENTION_HOURS=24
```

Default `PACKET_ACTIVITY_IFACE` to `AP_IFACE`. If capture cannot start, log one actionable error and continue serving the existing product.

## Dashboard data contract

Add a `FlowActivityChunk` type to `dashboard/src/data/types.ts` and include chunks in `GatewayData`.

Update:

- `dashboard/src/data/pocketbaseClient.ts` for initial session-filtered loading.
- `dashboard/src/data/useGatewayData.ts` for realtime create/update/delete events.
- `dashboard/src/model/sessionModel.ts` to decode, validate, sort, and clip samples to the visible frame range.

Never trust JSON blindly. Ignore malformed samples, negative counts, invalid bucket sizes, samples outside their chunk, and chunks whose flow is absent from the displayable flow set.

For large sessions, do not load an unlimited activity history. Extend the record-list helper with a time-range filter based on the selected zoom window, or add a dedicated endpoint that returns chunks for a session and time interval. Pagination must be handled explicitly; the current generic 1000-record limit is insufficient for this collection.

## Timeline rendering

Keep the existing domain hierarchy and individual flow rows.

For each flow row:

1. Render the pale full-lifetime baseline from `start` to `last_seen`.
2. Render client-to-remote payload above the centerline.
3. Render remote-to-client payload below the centerline.
4. Use a stable logarithmic height scale so one video transfer does not flatten smaller resources.
5. Show packet-only activity with a minimal one-pixel mark when payload bytes are zero.
6. Preserve selection and inspector behavior for the parent flow.

Recommended colors:

- Client-to-remote: amber or orange.
- Remote-to-client: blue or cyan.
- Connection baseline: the existing service color at low opacity.
- Missing/dropped capture interval: neutral hatched area, never silently rendered as idle.

Tooltips should say:

```text
14:03:12.150–14:03:12.200
Client → remote: 420 B payload / 3 packets
Remote → client: 16.0 KB payload / 12 packets
```

Use “activity,” “burst,” or “transfer” in the passive UI. Do not use “image,” “script,” “request,” “response time,” or “TTFB” without browser-provided evidence.

### Optional derived burst spans

The model may merge adjacent non-empty buckets into visual spans using a configurable idle-gap threshold, for example 100–200 ms. These spans are presentation-level derived data and should normally be calculated in the dashboard rather than persisted.

A small outbound span followed by inbound activity may be described as “possible exchange,” but it must carry an inferred label. HTTP/2 and HTTP/3 multiplexing prevents dependable pairing.

## Inspector changes

The flow inspector should distinguish three durations:

- **Connection lifetime:** first to last conntrack observation.
- **Observed active time:** number of non-empty activity buckets multiplied by bucket width.
- **Observed idle time:** connection lifetime minus covered active time, with missing capture intervals excluded.

Also show:

- Payload and wire bytes by direction.
- Activity-bucket resolution.
- Capture completeness or dropped-event warning.
- A short explanation that encrypted streams may contain multiple simultaneous application requests.

Do not calculate active time by simply summing overlapping inbound and outbound spans twice. A bucket is active if either direction has activity.

## Optional exact browser telemetry

Exact labels such as `hero.jpg`, resource type, request start, response start, and completion require evidence from the browser or an intercepting proxy. The preferred controlled-study extension is opt-in browser telemetry, not TLS interception.

Store browser observations separately, for example in `browser_resources`:

| Field | Purpose |
|---|---|
| `session` | Gateway observation session |
| `client_id` | Explicit participating browser/device identity |
| `page_id` | Browser-generated navigation identifier |
| `origin` | Resource origin |
| `path_or_hash` | Policy-controlled path, preferably omitted or hashed by default |
| `resource_type` | Image, script, fetch, stylesheet, media, and so on |
| `initiator_origin` | Browser-reported parent origin when available |
| `request_start` | Browser timing |
| `response_start` | Browser timing |
| `response_end` | Browser timing |
| `transfer_size` | Browser-reported size when available |
| `source` | Browser integration and version |

Correlate browser observations to flows by explicit client identity, destination hostname, and overlapping time. Store that conclusion separately with confidence; do not overwrite passive activity chunks.

The UI can then render verified resource spans above the passive burst track and show whether gateway traffic supports the browser report.

Browser telemetry must be separately enabled, consented, and documented because URLs and initiators are substantially more sensitive than the current gateway metadata.

## Testing strategy

### Pure unit tests

Add table-driven Go tests for:

- IPv4 TCP and UDP parsing.
- Client-to-remote and remote-to-client normalization.
- TCP options and ACK-only payload calculation.
- IPv4 fragmentation rejection or handling policy.
- VLAN-tagged Ethernet frames.
- Truncated and malformed packets.
- Infrastructure traffic rejection through `ObservationScope`.
- Bucket boundary behavior using a fake clock.
- Sparse chunk encoding and decoding.
- Counter overflow protection.
- Pending flow resolution and expiration.
- Bounded-channel drop accounting.

Use synthetic packet builders or small header-only fixtures. Do not add captures containing real user payloads.

### Integration tests

Create a deterministic packet-event replay that bypasses the raw socket and feeds metadata events into the aggregator. Verify:

- A 120 ms inbound transfer spans the expected 50 ms buckets.
- Two bursts separated by sufficient idle time remain visually separate.
- Opposite directions share the same canonical flow.
- Activity is related to the correct stored flow.
- Clearing observations removes chunks before flows.
- Expired chunks are removed without deleting flows.
- Capture backpressure does not block conntrack updates.

### Raspberry Pi validation

Run controlled sessions for:

- Idle phone.
- One small image on a simple HTTP/1.1 test server.
- Several parallel resources over HTTP/2.
- Video over QUIC/HTTP/3.
- Long-lived push or background connections.
- Simultaneous browsing from two clients.

Compare passive burst timing with browser developer timing only as validation. The passive UI must retain its uncertainty labels even when a particular controlled fixture happens to align perfectly.

Measure and record:

- CPU use on the minimum supported Pi.
- Additional memory use.
- Dropped capture events.
- PocketBase writes per minute.
- Database growth per hour.
- Dashboard load and rendering time for a 60-minute session.

## Acceptance criteria

Phase 1 is complete when:

- A short transfer is visibly distinct inside a longer connection.
- Inbound and outbound activity are distinguishable.
- Packet payloads and URLs are never persisted.
- Existing flow filtering applies to captured activity.
- Capture failure does not interrupt internet forwarding or existing observers.
- The dashboard never labels a passive burst as a confirmed HTTP request or resource.
- Missing or dropped capture data is visible rather than rendered as idle.
- Activity loading is bounded by session/time range and is not limited silently to 1000 records.
- Unit, replay, migration, backend, and dashboard tests pass.
- Performance and database-growth measurements are documented for the target Raspberry Pi.

## Implementation order

1. Add pure packet parsing, tuple normalization, and scope-filter tests.
2. Add the bounded packet-capture goroutine behind `PACKET_ACTIVITY_ENABLED`.
3. Add fake-clock bucket and sparse-chunk aggregation tests.
4. Add the `flow_activity_chunks` migration, upsert path, clearing order, and retention.
5. Add pending flow-key resolution without changing conntrack flow ownership.
6. Add dashboard types, bounded loading, realtime updates, and sample validation.
7. Render connection baselines with inbound/outbound activity overlays.
8. Add inspector activity/idle metrics and capture-completeness messaging.
9. Run deterministic replay tests and Raspberry Pi performance validation.
10. Consider browser telemetry only after the passive feature is stable.

## Likely pitfalls

- Treating a TLS record or traffic burst as one HTTP request.
- Polling the entire conntrack table at high frequency instead of using packet events.
- Writing one PocketBase record per packet or bucket.
- Capturing on the post-NAT interface and failing to match client flow keys.
- Counting TCP ACK-only traffic as application payload.
- Blocking packet capture on database writes.
- Silently losing activity when a flow relation is created later.
- Loading all fine-grained chunks for long sessions into the dashboard.
- Describing missing capture intervals as idle time.
- Adding payload-bearing packet captures to tests or logs.

These constraints are part of the feature contract, not optional polish.
