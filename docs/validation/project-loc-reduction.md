# Project LOC reduction result

Implemented on 8 October 2026 against `63c45218e8386226b69e77c6b00bec9bc7d020e6`, following the [approved plan](../proposals/project-loc-reduction.md). The candidate is the complete working tree, including new helpers, tests and the measurement script.

## Measured result

| Category | Baseline | Candidate | Net reduction |
| --- | ---: | ---: | ---: |
| Production source | 27,146 | 25,106 | **2,040** |
| Tests and verification tools | 13,730 | 13,568 | **162** |
| Build and configuration | 851 | 851 | 0 |
| Contract fixture data | 756 | 756 | 0 |
| Maintained scope | 42,483 | 40,281 | **2,202** |
| All non-documentation text | 46,993 | 44,791 | **2,202** |

Both targets were exceeded: 2,000 net non-documentation lines and 1,500 production lines. Production source is 7.5% smaller; all non-documentation text is 4.7% smaller. Nonblank non-documentation lines decreased by **2,091**. The 4,510 lines of migrations, dependency locks, static assets and domain data are unchanged.

| Area | Production delta | Verification delta | Combined delta |
| --- | ---: | ---: | ---: |
| Dashboard | −131 | −26 | −157 |
| Debug dashboard | −1,760 | +93 | −1,667 |
| Shared session state | −53 | 0 | −53 |
| PocketBase | −96 | −305 | −401 |
| LOC measurement script | 0 | +76 | +76 |
| **Total** | **−2,040** | **−162** | **−2,202** |

Reproduce from the repository root:

```sh
python3 scripts/count-loc.py --base 63c4521
python3 scripts/count-loc.py --base 63c4521 --json
```

The counter uses Git's inventory, including tracked files hidden by broad ignore rules and nonignored untracked additions. Deleted files are excluded. It counts physical lines and reports nonblank lines separately. Go `testsupport` files and browser harnesses count as verification. Documentation includes `docs/`, Markdown/RST, and the historical HTML reports. No generated output, dependency replacement, migration deletion, minification or comment stripping contributes to the result.

## Simplifications

- Removed the unused Lab renderer, its private mode/filter state, unused index facets, and the old Traffic timeline renderer. The active Lab graph, Traffic timeline and Remotion treemap remain.
- Traffic now computes its final identity and activity once. Removed the intermediate DNS/provider grouping that the active model immediately replaced; kept clip/activity caching, source timestamps, route evidence and version-1 export.
- Removed write-only shared UI/viewport fields, unused selectors and helpers, and 36 unused map CSS rules.
- Shared GPU mesh/attribute/animation mechanics between direct and joined-path traffic layers. Both shaders and their different mesh resolutions remain.
- Shared session loading, cancellation, polling, refresh and stale-data handling across the two libraries and legacy redirect.
- Consolidated timeline collection pagination and Lab HTTP authorization/body handling. Independent cursors, overlap/lookback rules, strict validation, response codes and request IDs remain explicit.
- Consolidated real PocketBase app/record setup, independent packet-byte builders and gate injection/verdict assertions. All **200 named Go tests** remain. Worker cleanup still runs before database teardown.

The proposed map workspace hook was dropped after implementation sizing: typing and adapter wiring consumed its savings. Existing clock behavior, activity-decoding policies and environment parsing remain direct; their optional consolidations offered little benefit or required a separate parity investigation.

## Verification

Nine final Traffic model/export scenarios were captured before production edits and match afterward: associated, independent, hidden-attribution, two-client, DNS-only, missing-time, capture-gap, mixed-resolution and route-revision data. Treemap markup also matches the baseline at three cursor positions. No expected hashes were updated to accommodate the rewrite. Active activity/cache assertions were moved to the final model; only tests of removed private paths were retired.

Workspace tests passed: **57 shared, 92 dashboard and 115 debug-dashboard tests**. Workspace lint and both production builds passed. Existing large-bundle build notices remain. Native `go test ./...`, the complete `go test -race -count=1 ./...` suite, `go vet ./...`, Linux ARMv7/ARM64 builds, route/capture/NFQUEUE namespace checks, and repeated Linux capture race tests passed.

Desktop Chromium 154.0.8037.98 acceptance, failure/compatibility and sustained-lifecycle checks passed: session filtering/refresh/offline retention, legacy redirects, recorded/live playback, treemap cursor/selection, bundle download, Lab replay, all simulated gate modes, unauthorized/offline/expired decisions and route teardown. Tests used the loopback fixture on port 8095, Vite on 5174/5175 (and 5188 for shader instrumentation), then a production preview on 5188. The lifecycle harness was updated to recognize the existing SVG map and current track list, replacing stale selectors for an older production layout. A 40-second live trace retained 600 events across 29.2 seconds, and leaving Lab released its subscription, playback driver, transient data and token. This is a bounded local scenario, not a multi-hour soak.

Map GPU checks passed for 222 shader assertions, directional burst travel, full/Pi mesh resolutions, fresh radius attributes, cached geography/label alignment, recorded playback across detail boundaries, rolling live time, pause, seek, faster replay and return to live. The production-preview workspace also passed location/direction filtering, consistent totals, both projections, drag expansion, saved preferences, theme changes and mobile overflow checks. Demo replay retained pause/seek across workspace changes. The render-budget sample counted 728 draws during playback, zero while paused and zero beneath the expanded timeline; Pi mode used one canvas and deferred tiled geography, while Equal Earth deferred the Mercator stack. The emitted MapLibre worker initialized successfully.

The 10,000-flow/8,000-DNS fixture loaded in 999 ms; sampled seeks took 44–84 ms. Fine-detail requests covered at most 10 seconds and six flows, with 20,994,086 bytes cached against a 50,331,648-byte budget and no pending requests at the final sample. Seven visible rows kept the DOM at 650 nodes. Median/p95 frame gaps were 16.7/33.3 ms, with a **1,466.7 ms maximum gap**. The known [cold-detail responsiveness concern](debug-dashboard.md#performance-and-lifecycle) remains open; these local measurements do not establish a before/after speedup or a Pi performance result.

Local logs and inventories are under `output/pocketbase-restructuring/loc-reduction/`; browser screenshots and the downloaded render bundle are under `output/playwright/`. These generated artifacts remain ignored.

## Remaining hardware acceptance

No test Raspberry Pi was available. Physical AP/NAT operation, device-specific NFQUEUE fail-open behavior, capture throughput/resource use, and display-Pi GPU performance still require the existing [PocketBase hardware acceptance](pocketbase-restructuring.md), [flow capture checks](flow-activity-raspberry-pi.md) and [Proxy Lab checks](proxy-lab-raspberry-pi.md). Local Linux namespaces and desktop Chromium do not establish those hardware results.
