# PocketBase restructuring implementation audit

The objective is the complete [restructuring plan](pocketbase-restructuring.md). This ledger tracks implementation and verification; unchecked requirements remain part of the goal. Baseline: `ea3ec5f`.

## Implementation

- [x] Delete unreachable proxy/lib/parser, observer route leftovers and obsolete routing/lab internals; retain live adapters and installation compatibility.
- [x] Inert gateway construction, serve-only startup, composed configuration and instance-owned session/resource state.
- [x] Register/test actual session hooks, committed session selection, demo restart and gate audit completion.
- [x] Acknowledged observation/route reset, deterministic bounded clear and defined fail-open armed-gate behavior.
- [x] Bounded shutdown/drain/join and partial-start rollback before closing PocketBase/trace/GeoIP dependencies.
- [x] Shared attribution/grouping input set, indexed DNS, effective installed attribution and exact-difference writes.
- [x] Private packet pipeline with all persistence off the aggregation loop, direct expiry and preserved generations/quality.
- [x] Destination input reuse and single IP deduplication; retain heartbeat/refresh semantics.
- [x] Catalogue simplification preserving atomic corrections, revision checkpoints and bounded examples.
- [x] Typed route admission/publication, store-owned transaction/read models and smaller scheduling owner.
- [x] Route history/expiry ownership, one maintenance scheduler and transaction-scoped module cleanup.
- [x] Timeline manifest/window reader with validated query types, shared activity codec and stable wire contract.
- [x] Frontend timeline/collection/realtime separation, route compatibility adapter and shared network access for map volumes.
- [x] Required lab queue readiness/mode-aware rules, one constructor and consolidated safe decision bookkeeping.
- [x] PocketBase-independent trace module; stable live/durable gate identity with compatibility fixtures.
- [x] Update Docker inputs, supported tool installation, architecture docs and obsolete README grouping description.

## Verification

- [x] Source-to-record attribution/grouping and unchanged-pass query/save measurements.
- [x] Actual hook failures, session transitions and demo restart tests.
- [x] Clear with in-flight observation/route work, dirty shutdown and partial-start rollback tests.
- [x] Route retry/idempotence, cancellation lease and manual controls characterization.
- [x] Shared Go/TypeScript manifest/window/route/gate fixtures across both transports and realtime.
- [x] Retention anchors, ordinary history, route-engine-off behavior and catalogue corrections.
- [x] All Go tests and affected race tests on the final state.
- [x] All workspace tests, builds and lint on the final state.
- [x] Linux ARMv7/ARM64 builds on the final state.
- [x] Final Linux namespace probe/capture/gate checks, 30 repeated capture/cancellation regressions and Linux capture race checks.
- [x] Existing-installation copy/upgrade compatibility and output/resource comparison.
- [x] Raspberry Pi acceptance or a precisely documented external blocker; do not claim verified completion without evidence.

## Current evidence

- Implemented the complete plan through step 7 in the working tree. No schema or migration changes; no commit, deployment or live-data modification.
- [Architecture guide](../implementation-guides/pocketbase-architecture.md) describes the resulting ownership, lifecycle and contracts.
- [Validation report](../validation/pocketbase-restructuring.md) records exact checks, compatibility limits and remaining release acceptance.
- Final native Go tests, all-package race suite, vet, frontend suites/lint/builds, ARMv7/ARM64 compilation and the production Docker builder pass. The shared package has 57 tests, dashboard 95 and debug dashboard 106.
- A stopped baseline-created database reopens with identical schema, table content, migration history and all 15 raw fixture records/IDs. Manifest and all 11 window collections match under the documented normalization.
- One warmed unchanged observation fixture drops from 18 to 7 SELECTs and from 3 to 0 derived saves with equivalent conclusions. No hardware throughput or CPU claim is made.
- Kernel testing exposed and fixed idle capture cancellation/double-close ownership. The regression failed before the fix and passed with IPv4/IPv6 capture in 30 repeated runs afterwards. The final Linux namespace matrix and Linux capture race checks pass.
- The user confirmed no test Pi is available and requested documentation of remaining hardware checks. Physical interface/mode/failure tests, matched load/retention soak, both browser transports on the gateway and an actual deployed database/rollback trial remain release acceptance, explicitly unchecked in the validation report.
