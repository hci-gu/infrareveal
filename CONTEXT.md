# InfraReveal Context

InfraReveal is a consent-based network metadata observability gateway. Linux
forwards client traffic through NAT independently of observation and probing.
The backend never needs HTTPS contents or client trust certificates.

## Domain terms

- Gateway: the machine running Wi-Fi, DHCP/DNS, NAT, capture, PocketBase and the dashboards.
- Session: one observation period. A closed recording has a fixed end; an active ephemeral session retains a rolling window. Closed sessions are not reopened.
- Client scope: a session-scoped device/lease identity. An IP address alone is not a person or a permanent device identifier.
- Traffic chunk: five seconds of captured counters for one client, supported service and exact destination binding. Sparse 50 ms samples contain directional wire bytes, payload-byte counts and packet counts; payload content is never retained.
- Service: a supported canonical registered-domain identity, including explicit aliases. Unknown or ambiguous traffic remains an independent endpoint.
- Activity block: a temporal group of payload-bearing activity for one client and service. Its span and union of active buckets are separate quantities; neither measures browser attention.
- Capture interval: confirmed complete, partial or unavailable observation coverage, including periods without traffic.
- Destination: versioned IP geography/provider context. Unknown and country-only geography remain explicit.
- Route evidence: a useful gateway-measured approximate path or a timestamped network invalidation. It is not the exact application path.
- Probe run: a durable admission charged before a method attempt, including failed, cancelled and interrupted attempts.
- Session runtime: the shared frontend window cache, revision handling and local playback.
- Diagnostics: optional bounded raw connection/DNS history, detailed probe output and Lab gate audit.

## Accepted architecture

The seven core application collections are `sessions`, `traffic_chunks`,
`capture_intervals`, `activity_blocks`, `destinations`, `route_evidence` and
`probe_runs`. Full diagnostics optionally adds `flow_diagnostics`, `dns_queries`
and `gate_events`. PocketBase auth/system collections are separate.

Captured traffic is the byte authority. Conntrack and DNS support bounded
in-memory identity/classification; traffic persistence never depends on finding
a stored connection. Compatible connections aggregate before persistence.
Wire counts include transport overhead and retransmissions and must not be added
to overlapping conntrack counters.

The starting defaults are 50 ms buckets, five-second chunks, approximately
400 ms flushes, ten seconds of provisional classification and a 45-second quiet
gap for blocks. Session policy pins alias rules and grouping parameters. Within
the correction tail, reclassification moves counts atomically; sealed labels
are snapshots. A restart starts a new capture epoch and seals persisted data.
No raw history is implied when diagnostics were not recorded.

Blocks are computed from sample intervals, not connection lifetimes. ACK-only
traffic does not extend a block. Capture interruptions create uncertain
boundaries. Retention clips totals and preserves crossing-block anchors. Missing
capture never becomes invented silence, bytes or a waveform.

Routing consumes captured traffic deltas, uses one paced worker, and preserves
finite target/attempt/storage budgets and cooldowns. Admission survives restart
and session deletion through its quota horizon. Publish terminal useful paths
with original measurement time, availability, expiry and exact binding. Reuse is
limited to the same session/network epoch. The network fingerprint governing
quotas is distinct from capture and session network epochs. Path publication and
optional enrichment are bounded; there is no persistent cross-session cache.

Both dashboards consume the same manifest, bounded map windows and activity
block API, invalidated by one session revision signal. The browser owns playback
and rendering; Go owns attribution, grouping and evidence selection.

## Implementation and development

[ADR 0003](docs/adr/0003-map-activity-storage.md) adopts this architecture.
[implementation-plan.md](implementation-plan.md) tracks the direct rewrite.
Development uses a fresh application database; old recordings, APIs and schemas
are not supported. Git retains the previous implementation. Reuse working
capture/probe/rendering code while deleting obsolete persistence and joins.

The continuous demo remains an active ephemeral session with configurable
retention (30 minutes by default). Diagnostics are off by default. Enabling the
optional Lab gate requires bounded audit storage and preserves the fail-open
contract in [ADR 0002](docs/adr/0002-opt-in-nfqueue-flow-admission.md).
