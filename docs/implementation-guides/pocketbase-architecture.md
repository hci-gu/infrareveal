# PocketBase architecture

InfraReveal stores map facts and temporal service activity. The accepted model is
[ADR 0003](../adr/0003-map-activity-storage.md). Fresh development data uses seven
application collections; detailed diagnostics optionally adds three. Auth and
PocketBase system collections are outside that count. This is a direct rewrite:
old recordings and APIs have no supported conversion or compatibility path.

## Ownership

| Module | Responsibility |
| --- | --- |
| `data` | Typed persisted facts, private collection schemas and revision writes |
| `gateway` | Configuration, session lifecycle, HTTP controls, cleanup and resource ownership |
| `observer` | Header capture, bounded DNS/connection correlation, aggregate persistence, coverage and block projection |
| `routing` | One physical probe worker, charged admissions, terminal evidence and historical selection |
| `timeline` | Bounded manifest, map-window and block queries with consistent pagination |
| `labgate` | Explicitly enabled fail-open queue control and mandatory audit |
| `debugtrace` | Independent bounded live metadata stream |
| `netmeta` | Address, tuple and packet-header parsing shared by capture and gate |

The shared frontend package consumes the manifest/window/block API. It owns
bounded window caching, revision-driven refetch, playback and filters. The two
apps render these product facts directly. Neither reconstructs flows,
attributions, episodes or membership associations from collection subscriptions.

## Storage and capture

- `sessions`: lifecycle, policy, monotonic revision, capture health and retained edge.
- `traffic_chunks`: five-second groups of sparse directional counters, keyed by
  capture epoch, client, service, versioned destination and exact route binding.
- `capture_intervals`: independently confirmed complete, partial or unavailable coverage.
- `activity_blocks`: derived periods of observed service activity.
- `destinations`: immutable versions of local IP/geographic context.
- `route_evidence`: useful terminal paths, one optional enrichment revision and network invalidations.
- `probe_runs`: reservations and outcomes which also enforce quotas and cooldowns.

AF_PACKET receives at most 256 header bytes and preserves original wire lengths
using AUXDATA. It does not store payload contents. A bounded queue feeds one
aggregation owner. Captured packets contribute immediately, even when conntrack
never sees the connection. Conntrack supplies identity/lifetime hints only;
its counters are never added to captured totals. DNS answers are bounded in
memory and uncertain shared endpoints remain independent traffic.

Connection generations and client MAC/lease identity prevent stale attribution
from crossing tuple or address reuse. A pinned session policy controls aliases,
50 ms buckets, a ten-second correction horizon and the 45-second quiet-gap rule.
Within the correction tail, sample contributions move atomically between
aggregates. Session capture epoch/generation fences reject obsolete writes even
after a previous aggregate has been deleted. Restart seals prior labels and
starts a new capture epoch.

Packets and heartbeats share an ordered source queue. A backwards wall-clock
jump cannot add traffic behind the sealed prefix: those packets are reported as
capture loss until their timestamps catch up. This keeps incremental block
summaries consistent with the immutable captured history.

Persistence flushes approximately every second. Source heartbeats travel behind
accepted packet events; coverage advances only through the confirmed source
watermark in the same transaction as counters. Queue/kernel drops produce
partial coverage. Disabled/unavailable capture never claims known zero traffic;
a crash leaves an unknown interval after the last committed watermark.

Blocks union payload-active sample intervals per client/service. ACK-only bytes
inside a block count toward its volume but do not extend its span. Traffic
outside blocks remains in map totals. A block is observed service activity,
not measured browser attention. Projection folds immutable history into a bounded
private prefix on each block and a session watermark, then replays only the
correction tail. Retention subtracts newly expired contributions. Chunk reads use
256-row keyset batches; unchanged summaries are not rewritten. Prefixes and their
watermark commit together and are excluded from the public contract.

## Lifecycle and retention

Construction is inert. `OnServe` acquires resources; migration/bootstrap commands
do not start capture or install firewall rules. Startup failure unwinds acquired
resources. Public session transitions join observation before changing the active
recording. Session hooks publish identity after commit and preserve concurrent
revision, capture and network updates.

`POST /api/infrareveal/simulation` starts (or joins) one three-minute synthetic
session. Its observer replaces hardware sources with paced Ethernet frames and
DNS lines, plus explicitly synthetic geographic snapshots. The production parser,
bounded queue, classifier, aggregation, persistence and projection remain shared.
A private simulator scope admits only its reserved documentation destination range;
live capture still filters those addresses. The simulation has no routing callback,
and manual probe requests reject its chunks.

`simulation_expires_ms` is both provenance and a durable cleanup marker. Separate
unique indexes allow one simulation alongside the real active recording; synthetic
session hooks never install the gateway's current session ID. Expiry, cancellation,
clear and shutdown join its observer before session deletion; startup deletes
orphaned simulation sessions. Failed cleanup retains ownership for retry, while the
source deadline independently stops generation. Session deletion cascades through
the normal cleanup hooks, including diagnostics and unreferenced destinations.

Clear disarms the gate, flushes audit, joins observation and route work, then
removes product observations in one transaction. Probe charges survive. Capture
restarts with fresh correlation state and a new epoch. Shutdown drains accepted
capture events before joining workers; a caller timeout leaves dependencies
available for a subsequent join. A transient final-write failure is retried.

Only active continuous sessions advance `retained_from_ms`; `started_ms` never
slides and ended recordings never reopen. The cutoff aligns to a source bucket.
Crossing blocks retain their identity and original start while displaying retained
counts. Destination versions disappear only after their last chunk reference.
Saved recordings keep product history until deletion. Probe charges have separate
network/scope retention and survive session deletion through their quota horizon.

## API and optional diagnostics

The public read API exposes session manifests, bounded map windows, paged blocks
and one coalesced revision stream. Map and block pages share at most eight pinned
WAL read transactions, each expiring after 60 seconds. Completed reads release
the transaction immediately; abandoned pages cannot pin the WAL indefinitely.
Capture keeps its own writer connection. Keyset pages scan at most 8,192 source
rows and target 2 MiB of traffic payload per response; auxiliary contexts have
separate bounded pages. There is no 4,000-row whole-window cutoff. Map windows
remain limited to 30 minutes. Compact reads group exact bindings and evidence
without sampling or dropping counters, while block detail retains raw bins.
Deletion, retention and capture-epoch changes invalidate obsolete snapshots.
Collection APIs are private, including operational probe admissions.

One gateway-owned worker runs a passive WAL checkpoint approximately each second
on its own connection, keeping routine syncing off capture commits. Timing varies
from 750–1,249 ms to avoid repeatedly colliding with capture and browser timers.
After fully checkpointing a WAL of at least 16,384 pages, it attempts truncation
with zero busy timeout; a reader or writer in the way defers reclamation. The
connection's timeout is restored before returning it to the pool. The writer retains an
automatic checkpoint fallback at 16,384 pages; shutdown or an unexpected worker
error restores the previous setting. SQLite's existing `synchronous=NORMAL`
setting is unchanged. Active read snapshots can delay checkpoint progress; the
60-second expiry limits how long any one reader holds it back. Overlapping reads
can still grow the WAL, so monitor it under sustained load. WAL files may retain
their allocated high-water size for reuse. This follows SQLite's [checkpoint scheduling
guidance](https://sqlite.org/wal.html#performance_considerations); the bundled
SQLite version is 3.53.3.

`DIAGNOSTICS_ENABLED=true` creates `flow_diagnostics`, `dns_queries` and
`gate_events`. Flow records include inline attribution. Optional writes use a
bounded independent queue; failure cannot hold up forwarding. Diagnostic age and
payload-byte limits apply independently of product retention. Detailed probe
output is optional and bounded on `probe_runs`.

The gate remains separately enabled and authenticated. Enabling it requires its
audit collection even in core mode. Startup marks interrupted audit rows as
unknown verdicts and discloses audit incompleteness. Live pending verdicts are
not evicted by diagnostic cleanup. No capture path depends on gate diagnostics.

## Development and verification

Stop the local server, then run `./scripts/dev-data.sh --reset` from the repository
root to replace disposable `pocketbase/pb_data` and seed an example recording.
Add `--diagnostics` for the full profile. Without `--reset`, an existing nonempty
directory is refused. `--dir /path/to/pb_data` supports an isolated fresh database.

Run `go test ./...`, `go test -race ./...` in `pocketbase` and `pnpm test`,
`pnpm lint`, `pnpm build` at the repository root. Cross-build Linux ARM64 and
ARMv7. See the [rewrite validation](../validation/map-activity-rewrite.md) for
the completed checks and the scope of the Pi capture measurements.
