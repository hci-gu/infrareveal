# Implementation plan: map and site activity

**Status: implemented and verified on 2026-10-15.**

See the [validation report](docs/validation/map-activity-rewrite.md) for test coverage, code-size changes and gateway measurements. The Pi smoke passed using real capture on isolated virtual interfaces; physical Wi-Fi testing was unavailable because the existing admin adapter was missing.

The seven-collection model in [report.html](report.html) is the new standard. This checklist replaces the previous route implementation plan.

Implement a direct rewrite against a fresh application database. Existing development recordings are disposable. Remove old writers, readers, schemas and APIs as their replacements are built. There is no data migration, legacy playback, compatibility layer, dual writing or shadow mode. Git provides the fallback for code; returning to an older version can use a fresh database for that version.

The steps below are the working order, not separate releases or approval gates. Reuse working capture, probe and rendering code where it fits the new model.

## Target structure

| Core collection | Purpose |
| --- | --- |
| `sessions` | Lifecycle, retention, policy, revision and current capture health |
| `traffic_chunks` | Captured traffic aggregated by client, service, destination binding and time |
| `capture_intervals` | Complete, partial and unavailable capture coverage |
| `activity_blocks` | Derived temporal service activity and summaries |
| `destinations` | Referenced versions of IP geography/provider context |
| `route_evidence` | Useful path publications and historical network invalidations |
| `probe_runs` | Durable probe admission, outcomes and quota accounting |

Full diagnostics optionally adds `flow_diagnostics`, `dns_queries` and `gate_events`. PocketBase auth/system collections are outside this application count.

Use the accepted starting defaults: 50 ms samples, five-second chunks, approximately 400 ms persistence flushes, a ten-second classification correction window and a 45-second quiet gap between activity blocks. Keep these configurable and pin the relevant classification/grouping policy per session.

## 1. Establish the new schema and vocabulary

- [x] Update `CONTEXT.md` and add an accepted storage ADR describing aggregate traffic, temporal activity blocks, bounded classification and optional diagnostics.
- [x] Replace the application migration history with a clean schema for the seven core collections, including required indexes, field bounds and access rules. Keep operational records admin-only.
- [x] Provide one development reset/bootstrap path for fresh application data and new demo fixtures. Remove old-recording import and compatibility requirements.
- [x] Define the shared traffic, block, destination and route types around the new model. Replace old types as consumers move; avoid maintaining parallel public contracts.

## 2. Rewrite capture, aggregation and activity blocks

Primary area: `pocketbase/observer`.

- [x] Persist captured traffic directly without requiring a stored flow or a successful conntrack match. Keep connection identity and DNS correlation in bounded memory; preserve unmatched traffic as unknown.
- [x] Aggregate chunks by session, capture epoch, client scope, service/independent endpoint, destination version, protocol, destination port, network epoch and chunk start. Keep source ports and flow IDs out of core storage.
- [x] Store directional wire bytes, payload-byte counts and packet counts in each sparse sample. Use captured wire bytes as the single accounting source; do not add overlapping conntrack totals.
- [x] Handle connection generations, tuple reuse, client lease changes and cache eviction conservatively. Retain compact evidence/confidence with classification; uncertain traffic must not inherit a stale service label.
- [x] Persist provisional chunks promptly. Support atomic attribution corrections within the bounded tail, and reject stale flushes using monotonic generations and conditional writes. Seal persisted labels on restart and start a new capture epoch.
- [x] Write capture coverage independently of packet arrivals, advancing only through confirmed persistence. Expose capture/queue loss and restart gaps.
- [x] Build a pure block projector over captured activity: group by client/service, union active intervals, split on the quiet-gap rule, and mark capture interruptions explicitly. ACK-only traffic does not extend a block.
- [x] Allocate sample intervals to blocks, allowing one connection to contribute to several blocks. Keep traffic outside blocks in the totals; distinguish block span from active time.
- [x] Implement rolling retention and session cleanup. Recompute retained block totals while preserving crossing-block identity/start anchors; remove destination versions only when unreferenced.

## 3. Simplify routing around admissions and evidence

Primary area: `pocketbase/routing`. Reuse the existing probe engine and its supported method/capability rules.

- [x] Replace budget/outcome state with transactional `probe_runs` reservations made before each method attempt. Failed, cancelled and interrupted attempts remain charged.
- [x] Enforce recorded-session lifetime limits, continuous-session hourly scopes, stable network/family rolling limits and cooldowns. Retain charges through their quota/suppression horizon even after session deletion; keep network identity distinct from capture and session epochs.
- [x] Preserve finite discovery: one paced worker, at most one automatic attempt per supported method and at most two methods per binding/scope, stopping on useful evidence. Keep the existing target, attempt, rate, byte and manual limits; pause after five completed no-gain comparisons.
- [x] Publish useful terminal paths as self-contained `route_evidence`, with original measurement time, availability, fixed expiry, exact binding and bounded hop evidence. Allow at most one meaningful enrichment revision per run.
- [x] Persist typed network invalidations and preserve the pre-window evidence needed for replay. Select evidence at the playback time without future information or stale-path resurrection.
- [x] Remove persistent cross-session caching, observation copies, confirmation/progress persistence and extra-budget controls. Reuse valid paths only within the same session/network epoch and derive current status from attempt records.

## 4. Replace the API and frontend data path

Primary areas: `pocketbase/timeline`, `packages/session-state`, `dashboard` and `debug-dashboard`.

- [x] Implement the session manifest, bounded map-window and paged activity-block endpoints. Return product data: traffic series, block segments, coverage, destinations and applicable route revisions.
- [x] Replace collection-by-collection subscriptions with one coalesced session revision signal. Use bounded window replacement/refetch semantics for updates, retention changes and reconnects.
- [x] Simplify the shared frontend runtime to window caching, local playback and filtering. Delete flow/attribution/episode/association joins and obsolete entity ownership machinery.
- [x] Move map tracks, destination volumes, waveforms and traffic animation to the new data contract. Preserve direction, unknown geography, service separation and totals at the playback cursor.
- [x] Add activity-block browsing and detail views showing service, observed span, active time, bytes, confidence and capture quality. Label inferred activity honestly; do not present it as measured browsing attention.
- [x] Update both dashboards and demo fixtures to the new model. Replace the default connection inspector with activity/service evidence; show raw diagnostic panels only when that data was recorded.

## 5. Finish optional diagnostics and remove obsolete code

- [x] Add the optional diagnostic profile with `flow_diagnostics` (including inline attribution), `dns_queries` and `gate_events`, bounded by time and bytes. A fresh core installation creates none of these collections.
- [x] Keep detailed probe output optional and bounded on attempt records. Ensure diagnostic failure does not block ordinary traffic observation or forwarding.
- [x] Preserve the Lab gate’s explicit enablement, fail-open behavior and audit requirements. Enabling the gate requires its audit storage.
- [x] Delete the old attribution/association/episode persistence, catalogue/checkpoints, route stores, legacy packet/traceroute paths, compatibility adapters, unused configuration and obsolete tests.
- [x] Update development setup, reset/cleanup commands, scripts and architecture guides to describe only the new standard. Keep useful existing regression tests by adapting them to the new contracts.

## 6. Verify the new implementation

Use focused fixtures and a fresh database. Validate the new model directly; running the old implementation alongside it is unnecessary.

- [x] Check byte conservation across aggregation, classification changes, block allocation, cursor movement and retention clipping. Account for incomplete capture separately.
- [x] Check repeated visits, overlapping services, one connection spanning multiple blocks, shared destination IPs, unknown traffic and capture gaps.
- [x] Check short connections missed by conntrack, tuple/lease reuse, bounded-cache eviction, duplicate/stale flushes and restart during a chunk.
- [x] Check route expiry/invalidation and replay, quota persistence across restart/session deletion, all-silent stopping and bounded evidence storage.
- [x] Run the applicable Go tests/race checks, frontend tests, lint, builds and supported ARM builds. Verify live map, pause/seek, recorded replay, activity details and optional diagnostics in the browser.
- [x] Smoke-test the new build on the gateway with representative traffic. Check database growth, write rate, memory and map-window latency; fix unbounded or clearly excessive work.
- [x] Confirm fresh startup creates seven core application collections, or ten with full diagnostics. Confirm the code has one active data path and the obsolete implementation is removed.

The rewrite is complete when the new model supports the map, activity blocks and optional diagnostics with the checks above passing. Old recordings and old APIs are outside the completion criteria.
