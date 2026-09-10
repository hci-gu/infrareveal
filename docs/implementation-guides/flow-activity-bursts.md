# Flow activity bursts

This guide describes the implemented metadata capture and visualization contract. Use the [Raspberry Pi validation procedure](../validation/flow-activity-raspberry-pi.md) for deployment-specific timing and resource measurements.

## Observation model

Conntrack is the authority for stored flow identity and lifetime. A flow key combines protocol, client IP, client source port, destination IP and destination port. `start` is the first observation; `last_seen` is the last scan containing the entry. Byte and packet fields are cumulative counters. The observer receives no explicit connection-close event.

A separate passive packet observer records when transfer activity occurs inside that lifetime:

```text
connection      ─────────────────────────────────────────
client → remote     ▪       ▪              ▪
remote → client       ████    ██              ███████
```

A connection bar is a sampled lifetime; an activity mark is a timestamped transfer derived from packet metadata. Neither identifies an HTTP request, browser resource, response time or TTFB. Encrypted HTTP/2, HTTP/3 and reused connections can carry multiple simultaneous exchanges.

Conntrack sampling is configured through `CONNTRACK_SAMPLE_MS`; see [live route discovery](live-route-discovery.md) for its interaction with route scheduling. Packet timing is independent of that sampling interval.

## Capture and normalization

The Linux collector uses an `AF_PACKET` socket on `PACKET_ACTIVITY_IFACE`, defaulting to `AP_IFACE` (`wlan0`). Capture on the client-facing interface preserves the tuple before/after NAT; uplink capture would need different correlation. The observer runs independently of forwarding, so capture failure leaves NAT and conntrack collection working.

The BPF filter retains at most a 256-byte snapshot. `PACKET_AUXDATA` supplies the original wire length through `tpacket_auxdata.tp_len`; `MSG_TRUNC` alone reports the length after BPF truncation. Using that truncated length rejects large packets and undercounts downloads. Missing/malformed auxiliary lengths must produce visible capture failure. Older recordings with missing samples cannot recover timing from cumulative counters.

`packet_parser.go` extracts observation time, session, canonical flow key, direction, protocol, wire bytes, transport payload byte count and TCP flags. The bounded packet prefix is discarded after parsing; payload contents are never persisted. TCP ACK-only packets add packet/wire counts but zero payload. QUIC remains opaque UDP payload.

Both directions normalize to:

```text
protocol | client IP | client source port | remote IP | remote port
```

Apply `ObservationScope` after normalization. Local, multicast, gateway-originated and excluded infrastructure traffic must not create activity. Packet capture cannot create stored flows; unresolved observations wait for conntrack attribution.

## Aggregation and configuration

Metadata events enter a bounded queue, then aggregate into sparse buckets and chunks. Database writes run separately from capture. Do not write one record per packet or bucket.

| Setting | Default | Supported range / meaning |
| --- | --- | --- |
| `PACKET_ACTIVITY_ENABLED` | `true` | Enable passive activity capture |
| `PACKET_ACTIVITY_IFACE` | `AP_IFACE` | Client-facing capture interface |
| `PACKET_ACTIVITY_BUCKET_MS` | `50` | 20–1000 ms |
| `PACKET_ACTIVITY_CHUNK_SECONDS` | `5` | 1–60 seconds |
| `PACKET_ACTIVITY_RETENTION_HOURS` | `24` | 1–8760 hours |
| `PACKET_ACTIVITY_MAX_PENDING_CHUNKS` | `4096` | 128–65536 unresolved/dirty chunks |
| `PACKET_ACTIVITY_EVENT_QUEUE` | `8192` | 256–131072 metadata events |

Open chunks flush every 400 ms; a five-second chunk does not mean five seconds of publication delay. Each bucket tracks directional payload bytes and packet counts. Chunk totals also retain directional wire bytes and OR-ed TCP flags. Retention removes expired activity in bounded batches without deleting parent flows or blocking capture.

Activity can arrive before its stored flow. Aggregate immediately, attempt relation resolution asynchronously and retain unresolved chunks for up to five seconds. If no in-scope flow appears, expire observations into `flow_activity_status.unmatched_events`.

Unmatched observations are separate from queue/aggregation loss in `dropped_events`. A matching timeout must not mark unrelated chunks or capture windows incomplete. The unmatched counter is cumulative for the collector lifetime. Historical quality flags remain unchanged because older combined counters cannot distinguish the original cause.

## Persistence contract

The migration creates activity collections before they are consumed. Clear-observations removes dependent activity before parent flows.

| Collection | Responsibility |
| --- | --- |
| `flow_activity_chunks` | Flow/session relation, chunk identity/time/resolution, sparse samples, directional wire/payload/packet totals, TCP flags, capture completeness and source update time |
| `flow_activity_windows` | Capture coverage and quality for a session interval, independent of whether any flow transferred bytes |
| `flow_activity_status` | Collector state, configuration and diagnostics |

`flow_activity_chunks.samples` is a versioned object:

```json
{
  "version": 1,
  "bucket_ms": 50,
  "chunk_ms": 5000,
  "samples": [
    [0, 420, 0, 3, 0],
    [50, 0, 16384, 0, 12],
    [100, 0, 8192, 0, 6]
  ]
}
```

Each tuple is `[offset_ms, payload_bytes_out, payload_bytes_in, packets_out, packets_in]`. Empty buckets are omitted. Sparse absence means silence only when capture coverage establishes completeness.

Consumers must validate versions, counts, bucket sizes, chunk bounds and flow identity. Ignore malformed data rather than inventing traffic. Do not blindly add overlapping fine/coarse observations or repeatedly sum updated cumulative chunks.

## Code ownership and loading

| Area | Location |
| --- | --- |
| Capture lifecycle, queues, flow resolution and retention | `pocketbase/observer/packet_activity.go` |
| Linux socket and original wire-length handling | `pocketbase/observer/packet_activity_linux.go` |
| Packet parsing and normalization | `pocketbase/observer/packet_parser.go`, `pocketbase/netmeta` |
| Pure bucketing | `pocketbase/observer/activity_buckets.go` |
| PocketBase chunk/window/status persistence | `pocketbase/observer/activity_chunks.go` |
| Session DTOs, bounded loading, realtime and cache ownership | `packages/session-state/src/data`, `packages/session-state/src/timeline` |
| Debug activity decoding and timeline projection | `debug-dashboard/src/shared/activity`, `debug-dashboard/src/model/sessionModel.ts` |
| Production map activity projection | `dashboard/src/map/timelineActivity.ts` |

Both dashboards consume the shared session runtime. Overview and fine detail have different responsibilities: keep detail requests paginated and bounded by visible/selected time ranges, with request cancellation and cache eviction. Compact cumulative summaries can cover the session without loading its entire fine-grained history. A fixed record limit must never silently truncate a requested interval.

## Visualization and evidence quality

In the debug timeline, preserve the connection baseline and parent-flow selection. Render outbound and inbound payload separately with a logarithmic scale; ACK-only activity remains visible as a minimal packet mark. Amber/orange outbound and cyan/blue inbound distinguish direction. The production map uses track colors and directional flow motion instead.

Use “activity,” “burst” or “transfer” in the passive UI. Show missing/dropped capture with text and hatching, not as idle time. Inspector totals must distinguish whole-connection counters from captured activity inside the selected window.

For active-time calculations, count the union of buckets active in either direction, not the sum of overlapping directional spans. Exclude missing coverage before describing remaining time as idle. Any presentation-level merging of adjacent buckets must retain original samples and must not imply measured request/response pairing.

Exact resource labels and browser timings would require a separate opt-in browser-telemetry extension. That extension is not part of passive capture: it needs its own consent, retention and correlation contract, and must not overwrite gateway evidence with inferred browser associations.

## Regression coverage

Use synthetic metadata or header-only fixtures, never real payload captures. Preserve coverage for:

- IPv4/IPv6, TCP/UDP, VLANs, options, ACK-only packets, fragments, malformed/truncated frames and infrastructure filtering.
- Direction normalization, bucket boundaries, sparse encoding, overflow protection and separated bursts.
- Real Linux socket/BPF handling of large frames and missing/malformed auxiliary lengths.
- Delayed flow resolution, unmatched expiry versus real capture loss, bounded queues and persistence backpressure.
- Migration, paginated/time-filtered loading, clear order, retention without parent deletion and graceful shutdown.
- Correct inbound/outbound rendering, validated sample decoding and visible incomplete coverage.

Run the [flow activity Pi procedure](../validation/flow-activity-raspberry-pi.md) for actual AP capture, controlled browser timing comparisons, forwarding isolation and a 60-minute resource/database-growth measurement. Local parser or replay tests alone do not establish target-device performance.
