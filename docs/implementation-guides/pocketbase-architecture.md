# PocketBase architecture

`pocketbase/main.go` constructs PocketBase, loads configuration, registers one
gateway instance, and starts the application. The runtime has no process-wide
mutable session or worker state. Migration filenames and collection names remain
unchanged; existing recordings and legacy route representations remain readable.

## Ownership

| Module | Responsibility |
| --- | --- |
| `gateway` | Configuration composition, application hooks, session/demo policy, startup/shutdown, HTTP adapters, clear and maintenance ordering |
| `observer` | DNS and conntrack intake, attribution, registered-domain grouping, packet activity, destination context, catalogue contributions and observation expiry |
| `routing` | Demand scheduling, probe lifetime, typed admission/publication transactions, evidence reads, budgets and route expiry |
| `timeline` | Validated manifest/window queries, independent collection cursors, route anchors and activity LOD |
| `labgate` | Optional fail-open queue controller, mode-aware firewall rules, control DTOs and durable audit |
| `debugtrace` | PocketBase-independent bounded live event stream; gateway owns its HTTP adapter |
| `netmeta` | Shared address/tuple normalization and metadata rules |

The shared TypeScript package keeps its public session interface while separating
HTTP access, timeline reads, older-gateway collection reads and realtime updates.
Its route adapter accepts old flat hops and current structured evidence, preserves
geography and alternatives, and compares timestamps as instants. Map summaries
use the shared transport; map aggregation remains in the dashboard.

## Lifecycle and write boundaries

Construction is inert. `OnServe` acquires trace, gate/audit, GeoIP, routing and
observation resources; command-line migrations and help do not start capture or
install firewall rules. A startup or listener failure unwinds acquired resources.
A failed startup is terminal for that runtime instance, and cleanup may be joined
again if the caller's deadline expires.

Session normalization runs before storage. Active-session selection is published
only in PocketBase's post-commit success hooks. Ending a session disarms its gate,
flushes audit outside the database transaction, and stores audit completeness.
The outer HTTP record/batch mutation boundary shares the gateway operation lock
with gate and route controls, clear and maintenance. Batch CRUD stays under its
original transaction; nested record hooks never acquire that lock. Internal session writes belong to
startup/maintenance; code must not acquire that lock from inside a transaction.

Clear acquires that boundary, disarms fail-open, flushes audit, stops and joins
observation workers, snapshots conntrack suppression, and waits for route reset.
Only then does it delete observations in dependency order, in batches of 200,
using PocketBase record deletion so realtime consumers see delete events. New
observation workers have fresh DNS references and packet state; suppressed live
conntrack tuples remain suppressed until they disappear. Sessions, domain
catalogue totals and persistent route spending survive. Optional old `packets`
and `traceroutes` collections retain the `deleted`/`skipped` response contract.
A failed quiescence/reset aborts deletion. A timed-out observation join recovers
intake after outstanding writes finish, under the same operation boundary.

Shutdown cancels maintenance, drains the gate before sealing audit intake, stops
observation producers and routing, drains accepted packet writes, then joins
workers before closing trace and GeoIP. Deadline errors stay visible and can be
joined again. Dependencies stay alive while an owner may still use them.

## Observation work

Each derivation pass reads flows, DNS, installed attributions, groups and links
once in a transaction. A temporary client/answer-IP index narrows DNS matching.
Grouping uses the effective installed attribution, including stronger evidence
that rejected a proposed downgrade. Full normalized field comparisons preserve
explanations and source times while avoiding unchanged saves and realtime events.
Stable group keys and the existing `activity_episodes`/`flow_associations` wire
names are retained. One newest-per-IP list feeds the separate destination lookup
worker. Destination `last_seen` retains its wall-clock heartbeat semantics.

Packet capture only enqueues metadata. A single aggregation owner handles bounded
queues, generations and acknowledgements; its private writer persists chunks,
capture status and windows. Capture loss and unmatched observations have separate
counters. Shutdown drains accepted events and reports incomplete persistence.
The Linux receive worker owns socket closure and checks cancellation through a
bounded idle receive timeout, so an idle interface cannot prevent joining it.
Activity payload version 1 is shared by storage and timeline coarsening.

The route coordinator owns demand, physical probe lifetime and retries. Its store
owns eligibility, budget reservation, terminal idempotence, atomic publication,
cache bindings and read projections. Publication retry keeps the original probe
identity and spending. Reset rejects obsolete results; cancellation retains the
physical worker lease until subprocesses and pipes have drained. Legacy traceroute
and pinned Scamper adapters remain available.

## Maintenance

One 15-second gateway scheduler orders cleanup; inactive packet detail keeps its
separate one-minute cadence and configured retention. Each rolling-session sweep
uses one transaction: collect catalogue contributions, expire observation records,
expire route evidence and terminal gate events, then advance the session's retained
edge. Every module uses the supplied transaction-scoped app.

Live flows, DNS supporting retained attribution, the latest pre-window route
revision and relevant evidence-event anchors survive. Ordinary session histories
survive rolling cleanup. Route cache/suppression expiry runs with the engine off
and with no rolling session; its 24-hour cutoff remains distinct from rolling
observation retention. Catalogue content-revision checkpoints preserve corrections,
late aliases and atomic counter transfers before raw evidence expires.

## Validation and compatibility

Shared JSON fixtures in `testdata/` cover manifests/windows, route evidence, and
live/durable gate decision phases. Go persists and reads these records; TypeScript
exercises timeline, collection and realtime paths. Regressions cover actual session
hooks/rollback, in-flight clear, packet generations/retry/drain, route publication
rollback and manual limits, and catalogue correction rollback.

Run `go test ./...` and `go test -race ./...` from `pocketbase`, and `pnpm test`,
`pnpm lint`, `pnpm build` from the repository root. Cross-build Linux ARM64 and
ARMv7. Kernel checks use the disposable namespace scripts and the Linux capture
test in `observer/packet_activity_linux_test.go`; they must not modify a live
network. See [validation evidence](../validation/pocketbase-restructuring.md) for
completed checks and the remaining hardware acceptance procedure.
