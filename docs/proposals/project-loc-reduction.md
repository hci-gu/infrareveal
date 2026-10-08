# Project LOC reduction plan

Implemented on 8 October 2026. See the [measured result and validation](../validation/project-loc-reduction.md). The proposal below records the baseline and original estimates.

Proposed against `63c4521` on 8 October 2026. This pass explicitly targets fewer maintained lines across the project while preserving current functionality. The working target is **2,000 net non-documentation lines removed, including at least 1,500 production lines**. Savings include the cost of replacement helpers, test infrastructure and new regression cases. These are planning targets; the final diff must establish the actual result.

The strongest opportunity is obsolete debug-dashboard implementation. Current callers bypass an entire Lab renderer and the old Traffic timeline renderer, and Traffic builds a historical grouping model before replacing its output. Removing those implementations offers substantially more reliable savings than another broad PocketBase reorganization.

The previous [PocketBase restructuring](pocketbase-restructuring.md) established lifecycle ownership and compatibility coverage. Keep that structure and its completed cancellation, drain, retention and transaction fixes. The accepted [metadata gateway ADR](../adr/0001-metadata-gateway-not-transparent-tls-proxy.md) and [opt-in gate ADR](../adr/0002-opt-in-nfqueue-flow-admission.md) remain in force.

The measured baseline uses physical lines in tracked text files:

| Category | Lines |
| --- | ---: |
| Production source | 27,146 |
| Tests and verification tools | 13,730 |
| Build and configuration | 851 |
| Contract fixture data | 756 |
| **Maintained scope for this pass** | **42,483** |
| Historical migrations, dependency locks, static assets and domain data | 4,510 |
| **All non-documentation text** | **46,993** |

Production source comprises PocketBase Go excluding migrations (11,885), dashboard source including its entry/build-source files (4,755), debug dashboard (6,736), shared packages (3,006), and gateway scripts/entrypoint (764). Browser harnesses, validation scripts and test support belong to verification even when their filenames do not contain `test`. Documentation includes `docs/`, Markdown/RST files and the two historical HTML reports.

At the working target, production source would be at most **25,646 lines**, and maintained scope approximately **40,483 lines**. Report the full non-documentation delta alongside these categories so code moved into fixtures, configuration or test helpers cannot disappear from the accounting. Leave the 4,510-line excluded group intact; lockfile churn or migration deletion does not earn credit.

Count from the baseline commit and the complete candidate tree, including new untracked files and excluding deleted files. Use Git's file inventory: the repository's broad ignore rules hide some tracked frontend `data/` paths from ordinary `rg`. Apply the existing formatting and report nonblank lines as a secondary check. Minification, comment removal, unrelated formatting, code generation and moving code between files do not qualify as simplification.

The non-overlapping opportunities below support an estimated **1,707–2,027 production lines removed**. Shared test construction can remove another **250–395 lines**. Reserve **135–350 added lines** for parity checks, adaptations and the measurement tool, giving approximately **1,600–2,300 net lines removed overall**. The 2,000-line target sits within that range; it is not a guaranteed outcome. Do not remove behavior or coverage to close a shortfall.

| Work item | Net production reduction | Additional test reduction | Confidence |
| --- | ---: | ---: | --- |
| Delete unused Lab renderer | 610 | No credit assumed | High |
| Retain treemap and remove old Traffic timeline renderer | 360–410 | No credit assumed | High |
| Build final Traffic projection once | 330–430 | New parity coverage budgeted | Medium |
| Remove unused runtime state and index features | 140–190 | No credit assumed | High |
| Delete other unused helpers and styles | 87 | No credit assumed | High |
| Share repeated map/session-list mechanics | 85–140 | Adaptations budgeted | Medium |
| Consolidate backend pagination and control envelopes | 95–160 | Adaptations budgeted | Medium |
| Reuse test setup, packet builders and gate assertions | 0 | 250–395 | Medium |

Execute the work in the following order, keeping each item reviewable and recording its net delta against the baseline.

1. **Establish the LOC ledger and capture the final user-facing contracts.**

   Add a small counter that reports production, verification, fixtures, build/configuration and total non-documentation lines. Count the counter itself. Record source inventories and use the same categorization before and after every change.

   Reuse existing fixtures and browser procedures. Add targeted characterization of final `buildTrafficModel` output, treemap selection and version-1 render-bundle export before deleting their intermediate implementation. Fixed clocks should make the comparison exact. Keep a scenario inventory so a lower test-file line count cannot hide lost assertions.

   This is the only preparatory item allowed to increase LOC on its own. Its cost is included in the overall target. Do not create a broad new test framework.

2. **Delete the unused Lab renderer and the old Traffic timeline renderer.**

   The active [Lab page](../../debug-dashboard/src/experiments/proxy-lab/ProxyLabPage.tsx#L140) renders `GraphViewport` and `LabReplayControls`. The following files total **610 lines** and have no path from a current application, script or registered composition entry point:

   | Relative to `debug-dashboard/src/experiments/proxy-lab/` | Lines |
   | --- | ---: |
   | `components/PipelinePlayer.tsx` | 263 |
   | `components/ActivityDataQuality.tsx` | 70 |
   | `components/ModeSwitcher.tsx` | 28 |
   | `components/PipelineFilters.tsx` | 50 |
   | `state/selectors.ts` | 15 |
   | Five files under `remotion/` | 184 |

   Delete that subtree and its unused imports/types. Keep the live activity-quality model, graph projection, recorded/live events, gate controls and replay navigation. `playerState.ts` still supplies active replay controls; remove only helpers that become unused. Update the stale implementation description in the Proxy Lab guide.

   [TrafficTreemap](../../debug-dashboard/src/experiments/session-playback/TrafficTreemap.tsx#L23) is the only runtime caller of [SessionComposition](../../debug-dashboard/src/remotion/SessionComposition.tsx#L38), and always requests `treemap`. Retain its treemap adapter and remove `TimelineScene`, unused timeline props, viewport calculations and private rendering helpers. Delete `debug-dashboard/src/model/timelineViewport.ts` when its final runtime caller disappears. Expected net reduction: **360–410 lines** after simplifying the remaining adapter.

   The active `TrafficTimeline`, both map projections, Remotion treemap and [render-bundle export](../../debug-dashboard/src/remotion/renderBundle.ts) remain. In particular, `selectSceneWindow` still serves export and must retain the version-1 scene format.

   Verify current Lab live/replay/control behavior, Traffic timeline, treemap cursor/selection, and exported JSON. Retire tests of unreachable private implementations only after retaining any assertions relevant to a live module. Do not count those test deletions in the forecast.

3. **Remove unused state and unrelated dead helpers.**

   In the shared [session store](../../packages/session-state/src/timeline/store/sessionStore.ts), remove unused `TimelineUIState`, `uiVersion`, their actions and the write-only `viewport`, together with their dead barrel exports and caller writes. Current Traffic preferences remain in their active owner. Delete unused `emptySelectedGatewayData`, `packages/session-state/src/timeline/selectors/selectGatewayDataWindow.ts` and stored `DetailPage.flowKey`; retain the actual page key and its flow-ID hash.

   After the Lab renderer deletion, remove Lab mode/filter/version fields used only by that renderer. Replace the `flow → turn-based → flow` gate-dialog translation with the gate mode already used by the active page. Keep observation mode, requested gate mode, replay cursor and current control status separate.

   The only live [temporal index](../../debug-dashboard/src/experiments/proxy-lab/model/temporalEventIndex.ts) caller asks for a time window. Keep that efficient query and remove unused facet indexes, facet arguments and `nearestBefore`. Active trace navigation keeps its current implementation and tests. Together, state and index cleanup should remove **140–190 production lines**.

   Delete `debug-dashboard/src/hooks/useWindowSize.tsx` (32 lines), `dashboard/src/map/timelineActivity.ts` (19 lines), and 36 complete unused rules in [map.css](../../dashboard/src/map/map.css). These add **87 production lines**. Validate CSS against dynamically constructed classes; `.atlas-wave-sent` and `.atlas-wave-received` are live and must remain.

   Verify session switching, preferences, seeking, detail ownership/eviction, rolling retention, Lab teardown and the bounded 36,000-event index scenario. The shared package is private, but all workspace callers and documented entry points must be checked before removing an export.

4. **Produce the final Traffic projection once.**

   [buildTrafficModel](../../debug-dashboard/src/experiments/session-playback/trafficModel.ts#L34) calls the 868-line [session model](../../debug-dashboard/src/model/sessionModel.ts), then replaces clip labels, confidence, grouping and association fields using the shared `flowTrackAt` module. It also rebuilds `serviceGroups` and `lanes`, discarding those produced by the old model.

   Keep flow eligibility, timing, activity calculation and useful clip caching. Build final identity and grouping once through `indexFlowTracks`/`flowTrackAt`. Delete superseded DNS/provider/known-service grouping, its intermediate group representation, discarded group cache and obsolete ordering helpers. The expected **330–430-line** reduction includes replacement wiring.

   Compare the **final Traffic model and exported scene**, rather than preserving the discarded intermediate model as the test contract. Cover independent traffic, explicit associations, hidden attribution, DNS-only records, two clients sharing an IP, missing timestamps, capture gaps, mixed activity resolutions and route revisions. Preserve minimum clip duration, frame positions, byte/packet totals, final labels, identifiers, selection and render-bundle fields. Assert that unchanged flow/activity inputs retain useful cache behavior.

   After this item, recompute actual savings. Items 2–4 plus the unrelated dead helpers are estimated to remove **1,527–1,727 production lines** before any backend or map consolidation. This is the first checkpoint against the production target.

5. **Consolidate repeated verification setup while preserving scenarios.**

   There are 12 real-PocketBase `Bootstrap` call sites in Go tests, plus repeated collection lookup/record construction/save blocks. Reuse existing package helpers first; share a small temporary-app and validated-record fixture module only where that deletes cross-package duplication. Examples include [gateway fixture setup](../../pocketbase/gateway/ephemeral_sessions_test.go#L14), [timeline contract setup](../../pocketbase/gateway/contracts_test.go#L31), [audit setup](../../pocketbase/labgate/audit_lifecycle_test.go#L225) and [observer setup](../../pocketbase/observer/activity_chunks_test.go#L95). Expected net test reduction: **160–240 lines**.

   Share explicit IP/TCP/UDP byte construction across `observer/packet_parser_test.go`, `netmeta/packet_test.go` and `labgate/nfqueue_test.go`: **40–70 lines**. Keep malformed-packet mutations and expected byte counts visible in the individual cases; fixture builders must not call production parsers to generate expected results.

   Reuse injection/verdict assertion helpers in `labgate/controller_test.go` and `controller_lifecycle_test.go`: **50–85 lines**. Keep context, packet ID, expected verdict and named ordering scenarios explicit. Preserve watchdog, overflow, duplicate verdict, failure drainage and timeout/retry cases. Avoid a generic command-interpreter test DSL.

   All helper files count toward verification LOC, even when Go requires an ordinary `.go` file to share them across packages. Run the same scenarios against real transactions and queues; ensure worker cleanup still precedes database cleanup.

6. **Consolidate the remaining repeated production mechanics where the diff pays for the helper.**

   | Module | Concrete change | Expected net reduction |
   | --- | --- | ---: |
   | Map traffic layers | Share repeated attributes, model lifecycle, quality mesh creation and draw uniforms in `FlowArcLayer.ts`/`FlowPathLayer.ts`; retain their distinct shaders | 45–75 |
   | Session-list loading | Reuse loading/cancellation/error/refresh mechanics across `SessionsPage`, `ExperimentsPage` and the debug redirect; preserve each polling policy and page markup | 25–40 |
   | Map workspace | Own repeated selection/focus/active-only/Escape and overview/timeline/inspector wiring once around the two projection adapters | 15–25 |
   | Timeline reader | Combine repeated collection query/error/cursor advancement in `timeline/reader.go` through a small private page loader with explicit named query specifications | 60–100 |
   | Lab control HTTP | Share authorization/body/error/response mechanics in `labgate/routes.go`; register simple commands through method values instead of switch dispatch | 35–60 |

   Map checks must preserve both projections, lazy Mercator loading, quality meshes, direction, dateline clipping, joined-hop continuity, missing spans, reduced motion and current render/update cadence. A helper that merely moves handlers into another file earns no savings.

   Timeline specifications must retain independent cursors, collection exhaustion, flow/chunk/window overlap, DNS lookback, related-record scoping, route anchors, overview omissions, limits and all response fields. Keep the typed response and route-reader ownership; avoid a general collection registry.

   Lab handlers must retain authorization-before-decoding, body limits, strict JSON validation, rate limits, origin checks, status codes, request IDs and distinct decision-conflict responses. Leave the queue controller and fail-open state transitions unchanged.

   Implement each consolidation as a separate diff. If replacement configuration, adapter plumbing and necessary tests consume the savings, drop the candidate from this LOC pass.

Keep the map clock simplification as a separate optional follow-up (**70–120 production lines**, uncredited above). It requires a parity spike for live following, explicit pause, rolling epoch, seeking, rate changes, reconnect and GPU update cadence. Shared activity decoding offers only **10–20 lines** because map/debug acceptance policies differ. Environment parser sharing is similarly small and has whitespace/case differences. Neither belongs on the critical path.

Every implementation diff must show production and total maintained LOC deltas and identify the removed implementation or duplicated operation. Preserve existing tests where they protect live behavior, adding coverage only for gaps exposed by these changes. The final acceptance checks are:

- Go package tests, affected race suites and vet; ARMv7/ARM64 builds after Go changes.
- Workspace tests, lint and both dashboard builds, followed by existing Traffic/Lab/workspace/browser rendering checks for affected views.
- Unchanged shared session/window/route/gate fixtures and version-1 render-bundle output; ordinary, rolling and demo behavior retained.
- Current capture cancellation, shutdown/drain, clear suppression, route budgets/publication retry and gate safety regressions remain intact. Run Linux namespace checks when the affected backend path warrants them.
- A baseline-to-final LOC report that includes all new helpers, test changes and fixtures. Explain any shortfall against 2,000 total / 1,500 production; do not label file moves as reduction.

No Pi is available. Existing [hardware acceptance work](../validation/pocketbase-restructuring.md) remains pending and must not be described as verified by this pass. No feature removal, migration rewrite, dependency/platform replacement or deletion of compatibility paths is required for the proposed savings.
