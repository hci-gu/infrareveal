# Debug dashboard UI redesign — implementation plan

Status: **Implemented and validated (M0–M6), 7 September 2026.** For ongoing checks, use the [browser validation procedure](docs/validation/debug-dashboard.md). Physical Raspberry Pi acceptance remains in the [Proxy Lab validation procedure](docs/validation/proxy-lab-raspberry-pi.md).

Design reference: [redesign-report.html](redesign-report.html), Workspace study 03, 7 September 2026. Its Traffic, Lab and Sessions previews define the accepted direction. Fixture data and report navigation are illustrative, not production behavior.

Target: `debug-dashboard`, with narrowly scoped shared session-runtime changes where required. Current gateway behavior is documented in the [Proxy Lab operator guide](docs/implementation-guides/proxy-lab.md), with outstanding hardware checks in the [Raspberry Pi validation procedure](docs/validation/proxy-lab-raspberry-pi.md). This redesign does not mark that validation complete.

## 1. Accepted design and scope

| Surface | Primary work | Required design |
| --- | --- | --- |
| Sessions | Select a live session or recording and launch a tool | A modern desktop source browser with categories, aligned rows, selected-source details and Open Traffic / Open Lab actions. Slate styling relates to Traffic, with more space and softer controls. |
| Traffic | Inspect traffic over time | A viewport-filling timeline workspace. One bottom bar combines the session navigator, scrubber and playback controls. A small event ledger and right inspector provide deeper evidence. |
| Lab | Follow traffic through gateway nodes | An independent graph application with trace selection, node inspection, observation branches and current gate controls. The graph is the main working surface. |

These requirements apply throughout implementation:

- Traffic and Lab remain separate routes and UI implementations. Neither contains a switch to the other. Both return to Sessions.
- Traffic has one middle density: approximately 36px flow rows and 26px group headers. No comfort/compact toggle.
- Traffic clocks, ruler labels and event-list timestamps use whole seconds. Full source precision remains intact for sorting, correlation, raw records and exports.
- The session navigator sits beside Play below the Traffic tracks, with a visible drag handle and explicit −5s / +5s controls. There is no second navigator above the timeline.
- Timeline and node-canvas space take priority over large page headings, aggregate cards and decorative charts.
- Sessions and Traffic share restrained desktop styling. Lab has its own layout and graph controls; do not build a common Traffic/Lab editor shell.
- Density comes from layout and reduced repetition. Do not shrink the whole UI or obscure source identity, uncertainty, coverage or current control state.

This is a frontend redesign using existing metadata, APIs and control behavior. A new capture pipeline, schema migration, gateway policy, dependency upgrade campaign or production `dashboard` redesign is outside this plan. Preserve the controlled client, recorded render-bundle export and existing secondary utilities.

## 2. Current code and implementation boundaries

Paths below exist today. Component names suggested later describe new responsibilities and can be adjusted during implementation.

| Area | Existing code | Planned change |
| --- | --- | --- |
| Routes | [App.tsx](debug-dashboard/src/App.tsx) | Keep `/`, `/timeline/:sessionID`, `/proxy-lab/:sessionID`, `/controlled-client`, bare-route redirects and legacy session/time query handling. |
| Session launcher | [ExperimentsPage.tsx](debug-dashboard/src/pages/ExperimentsPage.tsx), [sessionGroups.ts](debug-dashboard/src/pages/sessionGroups.ts) | Replace experiment cards with the source browser. Retain refresh, connection states and multiple active sessions. |
| Styling | [index.css](debug-dashboard/src/index.css), [button.tsx](debug-dashboard/src/components/ui/button.tsx), [formatters.ts](debug-dashboard/src/views/formatters.ts) | Add scoped desktop tokens and controls; standardize display time without changing stored data. |
| Traffic page | [SessionPlaybackPage.tsx](debug-dashboard/src/experiments/session-playback/SessionPlaybackPage.tsx) | Split orchestration, transport, tracks, ledger and inspector. Replace the KPI strip, fixed video wrapper and 390px feed column. |
| Traffic projections | [sessionModel.ts](debug-dashboard/src/model/sessionModel.ts), [timelineViewport.ts](debug-dashboard/src/model/timelineViewport.ts), [selectSceneWindow.ts](debug-dashboard/src/timeline/selectors/selectSceneWindow.ts) | Reuse flow identity, grouping and activity projections. Adapt viewport geometry and row selection for interactive use. |
| Recorded rendering | [SessionComposition.tsx](debug-dashboard/src/remotion/SessionComposition.tsx), [renderBundle.ts](debug-dashboard/src/remotion/renderBundle.ts) | Preserve deterministic rendering and bundle export. Separate interactive pane dimensions from fixed export dimensions. |
| Session data | [useGatewayData.ts](packages/session-state/src/data/useGatewayData.ts), [pocketbaseClient.ts](packages/session-state/src/data/pocketbaseClient.ts), [types.ts](packages/session-state/src/data/types.ts) | Reuse manifests, overview/detail loading and DTOs. No per-row session-controller instances. |
| Shared time/cache | [sessionStore.ts](packages/session-state/src/timeline/store/sessionStore.ts), [sessionController.ts](packages/session-state/src/timeline/transport/sessionController.ts) | Retain canonical cursor, server live edge, range cache, paging and reconciliation. Preserve existing public UI-state compatibility. |
| Lab orchestration | [ProxyLabPage.tsx](debug-dashboard/src/experiments/proxy-lab/ProxyLabPage.tsx), [proxyLabStore.ts](debug-dashboard/src/experiments/proxy-lab/state/proxyLabStore.ts) | Reorganize around graph inspection; separate observation mode from gate configuration. |
| Lab graph/replay | [graphLayout.ts](debug-dashboard/src/experiments/proxy-lab/model/graphLayout.ts), [projectRecordedEvents.ts](debug-dashboard/src/experiments/proxy-lab/model/projectRecordedEvents.ts), [projectProxyScene.ts](debug-dashboard/src/experiments/proxy-lab/model/projectProxyScene.ts), [PipelineGraph.tsx](debug-dashboard/src/experiments/proxy-lab/remotion/PipelineGraph.tsx) | Reuse topology, event paths and deterministic projections. Add graph navigation and inspectable nodes. |
| Lab controls | [PipelinePlayer.tsx](debug-dashboard/src/experiments/proxy-lab/components/PipelinePlayer.tsx), [QueueInspector.tsx](debug-dashboard/src/experiments/proxy-lab/components/QueueInspector.tsx), [GateHealth.tsx](debug-dashboard/src/experiments/proxy-lab/components/GateHealth.tsx), [GateArmDialog.tsx](debug-dashboard/src/experiments/proxy-lab/components/GateArmDialog.tsx) | Reorganize presentation while preserving replay, authorization, decisions, deadlines and flow/strict/DNS modes. |
| Activity quality | [activityDataQuality.ts](debug-dashboard/src/experiments/proxy-lab/model/activityDataQuality.ts), [decodeActivityChunk.ts](debug-dashboard/src/shared/activity/decodeActivityChunk.ts) | Reuse decoding and quality semantics. Extract pure capture-quality logic to `shared/activity` if needed by Traffic; keep stream/control presentation specific to Lab. |

### State and rendering decisions

- Use the existing React/TypeScript, SVG, CSS, Zustand and Lucide facilities. The fixed gateway topology does not require a graph library.
- Render interactive Traffic tracks in a pane-sized React/SVG surface with virtualized rows. Reuse projection data with Remotion; do not scale the 1440 × 810 export canvas to render desktop labels and controls.
- Keep one canonical session cursor. Extract existing playback synchronization into an adapter for the active route. Only one driver advances playback; removing the embedded Traffic Player must not leave a competing frame clock running.
- Keep new Traffic pane sizes, dock tab, filters and scroll preferences local to the debug UI. Preserve compatibility for existing `sessionTimelineStore.ui` fields.
- Extend Lab state with selected node, graph transform and branch visibility alongside selected trace/event. Lab does not consume Traffic layout preferences.
- Persist useful layout and inspection preferences per tool/session with a versioned local key. Never persist operator tokens, pending decisions or an assumption that the gateway is armed.

## 3. Delivery sequence

Check a milestone only after its implementation and acceptance checks pass. Keep changes independently reviewable and buildable.

| Milestone | Deliverable | Depends on |
| --- | --- | --- |
| M0 | Baseline, visual tokens and route/state boundaries | — |
| M1 | Sessions source browser connected to real sessions/manifests | M0 |
| M2 | Traffic viewport, tracks and resizable panes | M0 |
| M3 | Integrated Traffic transport and linked evidence | M2 |
| M4 | Independent Lab graph and trace inspection | M0 |
| M5 | Lab queue/control integration and state separation | M4 |
| M6 | Integration, performance, validation and handoff | M1, M3, M5 |

Sessions, Traffic and Lab can be developed independently after M0. They must not depend on a shared editor layout.

Implementation record (7 September 2026):

| Milestone | Implemented in | Evidence |
| --- | --- | --- |
| M0 | `shared/ui/desktop.css`, preferences, splitters and copy controls; scoped Lab styles; shared controller request ownership and cancellation | Baseline checks, route/focus/export browser checks, shared controller regression tests |
| M1 | `pages/ExperimentsPage.tsx`, `pages/sessions/sessionSummaries.ts` and `useSessionSummaries.ts` | Summary/filter unit tests; selected-ID, multiple-live, failed-summary and offline browser checks |
| M2 | `TrafficTimeline.tsx`, `trafficModel.ts`, `traffic.css` and pane orchestration | Desktop/narrow screenshots; virtualized 10,000-flow recording profile |
| M3 | `TrafficTransport.tsx`, `useTrafficPlayback.ts`, inspector, ledger, utilities and secondary treemap | Time/coverage/LOD tests; scrubbing, zoom, linked selection, keyboard splitters, focus and bundle download checks |
| M4 | `GraphViewport.tsx`, `traceNavigation.ts`, `NodeInspector.tsx`, `LabReplayControls.tsx` and `lab.css` | Path and projection suites; node/branch/zoom browser checks; independent layouts |
| M5 | `useLabControl.ts`, observation/configuration state, existing gate forms, health and NOW queue | Independence/expiry tests; authenticated flow/strict/DNS, pause/resume/drain/disarm, invalid-token, offline and in-flight browser checks |
| M6 | `debug-dashboard/test-support`, README and validation artifacts | [Browser validation procedure](docs/validation/debug-dashboard.md) |


## 4. M0 — Baseline and visual foundation

- [x] Record current frontend test/build/lint results and route behavior. Separate existing failures from redesign regressions.
- [x] Capture active-session, recording, partial-capture and Lab-queue reference views. Treat the report as a design reference, not an API contract.
- [x] Add scoped surface, text, border, selection, focus and status tokens. Use slate surfaces for Sessions/Traffic, cyan/amber for traffic direction, violet for derived evidence and hatching for incomplete coverage.
- [x] Establish readable type, tabular numbers, subtle separators and softer corners. Essential text stays readable at native scale; do not reproduce the smallest decorative report text in controls.
- [x] Share useful primitives such as buttons, fields, tabs, labels, tooltips and accessible splitters. Keep tool-specific layout components separate.
- [x] Define route cleanup: cancel obsolete requests, stop outgoing playback/trace subscriptions and clear source-specific stale selection while preserving explicit deep links.
- [x] Keep Settings, refresh, controlled-client access, render-bundle export and existing data-clear confirmation reachable in secondary menus. Retain the treemap as a secondary Traffic view during the redesign; it is not the default surface or an extra primary toolbar segment.

**Acceptance:** tokens do not restyle the production dashboard; existing routes/deep links still resolve; baseline results and retained secondary actions are documented.

## 5. M1 — Sessions source browser

Refactor `ExperimentsPage` into a header, categories, source table and selected-source panel. Suggested components: `SessionBrowser`, `SessionList`, `SessionDetails` and a local `useSessionSummaries` hook.

- [x] Show All sessions, Live and Recordings with real counts. Preserve multiple active sessions instead of assuming the report's single live example.
- [x] Search by name, ID and displayed date. Sort newest first with a stable ID tie-breaker. Keep selection stable during refresh/filtering and identify when it is outside the filtered list.
- [x] Show name, start date, live/recorded state, duration, flow count and gate-audit quality in aligned rows. Add ID, DNS count and full metadata in selected-source details.
- [x] Use `getSessions` for the list and `getSessionManifest` for summaries. Fetch visible/selected rows with bounded concurrency, cache by session, cancel obsolete requests and refresh active summaries. Do not start `useGatewayData` per row or fetch all activity to populate the list.
- [x] Show absent counts, collection-fallback manifest data and unspecified audit completeness as unavailable/unknown. Closed duration uses start/end; active elapsed time uses synchronized server time when available.
- [x] Put Open Traffic and Open Lab in selected-source details. Both launch the selected session ID. Source selection belongs here rather than being duplicated inside both tools.
- [x] Cover loading, empty gateway/search, offline with retained data, failed summary and deleted-session states. Refresh and controlled-client access remain secondary.
- [x] Support keyboard source selection and normal link behavior. Narrow screens can use a focused list/details arrangement with launch actions still reachable.

**Acceptance:** any selected recording opens both tools with that recording, not the current session or a fixture. A failed summary does not block the list. Styling is cohesive with Traffic and more spacious.

## 6. M2 — Traffic working surface

Suggested responsibilities under `experiments/session-playback/`: `TrafficWorkspace`, `TrafficToolbar`, `TrafficTimeline`, `TrafficTrackHeader`, `TrafficInspector`, `TrafficLedger` and local workspace state. Keep `SessionPlaybackPage` focused on source/runtime orchestration.

### Layout

- [x] Fill the viewport with small source/status and tool bars, main timeline, right inspector, lower event ledger and status bar. Remove the oversized heading, aggregate cards, fixed video wrapper and duplicate live feed.
- [x] Put endpoint search, client filter and Events/Inspector visibility controls in the toolbar. Back to Sessions is its only source/tool navigation.
- [x] Use independently scrolling panes, sticky track headers and a sticky ruler. The timeline remains the largest central pane with default inspector and ledger open.
- [x] Add pointer/keyboard splitters, minimum pane sizes, persisted sizes and restore-default-layout behavior. Closing panes expands the timeline without scaling text.
- [x] Use one row density. On smaller desktop widths, collapse optional panes before reducing label legibility; retain horizontal timeline navigation.

### Track projection and rendering

- [x] Project client → supported activity → flows. Keep unsupported, ambiguous and provider-only associations under independent traffic. Reuse the high/medium association threshold.
- [x] Preserve endpoint/socket identity and stable IDs across grouping, live updates, filtering and virtualization. Hostname attribution and activity association remain separate relationships.
- [x] Show endpoint, compact protocol/IP context, confidence and directional lifetime counters in headers. Keep clip labels short and put detailed fields in the inspector.
- [x] Draw observed lifetime envelopes and actual received/sent activity bins. Respect wire versus payload counts and available capture resolution. Never distribute a lifetime counter across a clip or generate decorative waveforms.
- [x] Add supported DNS and attribution/association evidence rows. Each marker retains its own source record and timestamp; a group's DNS history must not all become evidence for its first flow.
- [x] Align coverage with the time axis. Distinguish idle with complete capture, not-yet-loaded intervals and known capture loss with both text and visual treatments.
- [x] Virtualize long row lists and render activity only for the visible window plus overscan. Retain selected IDs when rows leave view and preserve scroll anchors during incoming data.

**Acceptance:** large recordings stay navigable; the timeline dominates at 1440 × 900; every envelope, bin and marker has real source evidence. Grouping does not obscure endpoint identity or imply unsupported attribution.

## 7. M3 — Traffic transport and linked evidence

### One integrated playback bar

- [x] Place −5s, Play/Pause, +5s and the current whole-second clock beside the full-session navigator below the tracks. Include a prominent scrub handle, start/end labels, visible-window outline, speed/window selectors and Go live/End.
- [x] Keep the navigator's session range distinct from the main timeline's zoom window. Derive its overview from available activity aggregates and coverage. If full-session activity is unavailable, show a useful time/coverage rail with unavailable regions; do not invent a complete waveform or load the whole recording at fine resolution.
- [x] Use one seek action for navigator dragging, ruler interaction, step buttons, keyboard commands and record selection. Clamp to session bounds and update the shared cursor and required data window together.
- [x] Display seconds without rounding source timestamps. Preserve deterministic ordering within the same displayed second and full timestamps in raw records/copy/export.
- [x] Support Space for playback, arrows for one-second steps and Shift + arrows for five-second steps, scoped to Traffic. Respect native behavior for focused buttons, inputs, selects, details and editable text.
- [x] Keep the playhead visible during zoomed playback and stepping. Zoom about the cursor, preserve time and keep horizontal scrolling independent of vertical row scrolling.
- [x] Scrubbing live history stops following while capture and server live edge continue. Go live resumes following explicitly. Recordings have a fixed end and no live badge/action.
- [x] Handle buffering, failed detail loads, disconnection, session end and rapid seeks. Keep dragging responsive without a request per pointer pixel. Preserve URL time links without adding browser history on every frame.

### Selection, inspector and ledger

- [x] Synchronize clip, evidence-marker and ledger selection by stable ID. Ledger selection reveals the corresponding track/time; clip selection opens evidence without losing zoom.
- [x] Provide Events, DNS and Flow records tabs with sortable columns, pinned identifiers, copy actions and virtualized rows. Label loaded/filtered scope.
- [x] Populate inspector sections for socket/state, first/last seen, lifetime counters, visible-window activity, packet/capture coverage, DNS answers/aliases, attribution explanation, separate association, destination/ASN/provider, approximate route and raw fields.
- [x] Load missing details for the visible interval and selected flow using existing range APIs and caches. Preserve selection identity across row virtualization and detail-page eviction; show loading when selected evidence must be fetched again.
- [x] Keep lifetime and window counters distinct. Avoid double-counting overlapping LOD buckets. Show capture resolution and incomplete coverage beside window measurements.
- [x] Cover no selection, missing enrichment, filtered selection and deleted sources. Label route probes as a gateway approximation, not application latency.
- [x] Preserve recorded render-bundle export with deterministic selectors. Interactive pane dimensions must not change export dimensions or source timestamps.

**Acceptance:** navigator, ruler, playhead, URL and selected records agree after repeated seek/zoom/filter operations. Displayed results resolve to raw evidence. No subsecond clutter or density switch appears in the primary UI.

## 8. M4 — Independent Lab graph

Suggested components under `experiments/proxy-lab/`: `LabWorkspace`, `GraphViewport`, `TraceSelector`, `TraceNavigation` and `NodeInspector`. Adapt existing graph/render components and projections rather than rebuilding the gateway model.

- [x] Give the graph the main working area with a dedicated Lab header, source label, observation mode, trace selector, branch toggle and graph controls. Do not import Traffic's timeline/dock layout or add a Traffic switch.
- [x] Lay out client → wlan0 → conntrack → flow gate → FORWARD → NAT → remote. Preserve inbound, DNS-gate and reject/drop paths from `graphLayout.ts`, including paths omitted by the simplified report fixture.
- [x] Arrange DNS and passive capture/attribution/enrichment/route/storage branches around the main path. Distinguish forwarding from observation; enrichment/capture must not appear to be a blocking forwarding hop.
- [x] Support pan, zoom, Fit path, reset view and optional expanded canvas. Node text stays readable at default fit; the graph is not an unchangeable scaled screenshot.
- [x] Select nodes by pointer/keyboard. Keep selected node separate from selected trace/event. Show relevant facts, related source events and provenance in the side inspector.
- [x] Filter/select real traces by client, endpoint and protocol. Keep the selected trace stable during arrivals; identify when a filter or retention boundary excludes it.
- [x] Implement Previous / Next stage for the selected trace's projected path, including held, rejected, DNS and inbound cases. Do not advance a held trace through forwarding without a corresponding verdict.
- [x] Retain deterministic replay, slow motion and event/frame inspection in Lab-specific secondary trace controls. Any time control stays subordinate to the graph; Lab must not become a multi-track Traffic editor.
- [x] Preserve derived timing labels for reconstructed stage transitions. Connector lengths, node positions and moving tokens are explanatory, not measured hop latency.
- [x] Retain `projectRecordedEvents`, `mergeLiveEvents`, temporal indexing and bounded ephemeral retention. Avoid duplicating live/durable events when detail arrives. Show stream gaps and unavailable history honestly.
- [x] Cover empty traces, unavailable evidence, disconnected streams and incomplete recordings. Reduced motion retains direction and selection without depending on token animation.

**Acceptance:** the user can follow and inspect connections through relevant nodes, holds and rejects. Lab visibly works as an independent graph tool, and replay remains grounded in observed or explicitly derived events.

## 9. M5 — Lab observation modes and current control

The current `ProxyLabMode` combines `replay`, `live-observe`, `turn-based`, `strict` and `dns`. The approved header shows observation modes only. Implement this separation explicitly; do not remove gate capabilities to match the simplified sketch.

- [x] Separate observation mode (`replay` / `live-observe`) from gate configuration (`flow` / `strict` / `dns`) in Lab state/components. Derive effective armed mode from `GateStatus`. Changing a view never changes gateway policy.
- [x] Put gate setup in a focused control panel beside the queue: targets, operator token, flow/strict/DNS settings and explicit arm action. Retain pause/resume, drain/disarm and strict tuple constraints.
- [x] Keep the current queue in a clearly labeled NOW section beside node inspection. Its updates, waits and deadlines use current server/control time, independent of the historical cursor.
- [x] Replaying an active source continues applicable current-control polling and distinguishes historical evidence from live decisions. Closed recordings show durable audit with current decision actions unavailable.
- [x] Preserve authorization, per-command/decision in-flight disabling, verdict responses, conflict refresh, expiry, watchdog outcomes and reconciliation. Selecting historical evidence cannot re-enable an expired decision.
- [x] Keep control connectivity, armed/paused state and targets visible. Put capacity, drop, watchdog and audit diagnostics in expandable details rather than large metric cards.
- [x] Keep capture loss, browser trace delivery loss and durable gate-audit loss separate. Reuse `deriveActivityDataQuality` and existing selectors. Detailed diagnostics may collapse, but active degradation indicators remain visible.
- [x] On route/source changes, abort stale requests and clear stale decisions, selections and credentials according to existing lifecycle behavior. Demo fixtures remain explicit and cannot issue real gate mutations.

**Acceptance:** replay and observation-mode changes neither mutate the gate nor rewind the queue. Flow/strict/DNS operations retain existing authenticated contracts. Offline, expired and recorded decisions cannot appear actionable.

## 10. Data presentation contract

Use the current [shared DTOs](packages/session-state/src/data/types.ts) and [Lab contracts](debug-dashboard/src/experiments/proxy-lab/types.ts). A field is not assumed present solely because it appears in the report.

| Data | Placement | Interpretation |
| --- | --- | --- |
| `Session`, `SessionManifest` | Sessions list/details and source/status bars | Manifest totals, server clock, coverage and fixed recording end have distinct meanings. Missing counts/audit flags remain unknown. |
| `Flow` | Traffic tracks/ledger/inspector; Lab trace/node facts | Socket, state and lifetime counters are observations. Observed client IPs are not an inventory of all connected devices. |
| `FlowActivityChunk`, windows/status | Traffic activity/coverage; Lab capture evidence | Use decoded bins and available LOD. Preserve wire/payload, direction and completeness. Missing capture is not zero traffic. |
| `DNSQuery`, `FlowAttribution` | DNS ledger/markers, hostname evidence; Lab DNS/attribution nodes | Preserve answers, aliases, confidence, source and explanation. A hostname candidate does not replace the endpoint. |
| `ActivityEpisode`, `FlowAssociation` | Traffic groups and association details | A separate inference with its own confidence. Only supported client-specific links create parent groups. |
| `Destination`, `Route` | Traffic network details; Lab enrichment/route nodes | Optional provider/ASN/coarse location. Gateway probes do not measure the client's application path or response time. |
| `PipelineEvent`, stream metadata | Lab traces, node events and delivery status | Preserve occurrence/processing time, sequence, direction and observed/derived provenance. Respect retention and gaps. |
| `GateDecision`, `GateStatus`, durable `GateEvent` | Lab current queue/configuration versus historical evidence | Pending state is not reconstructed from replay. Keep actor, reason, verdict source, deadline and audit quality inspectable. |

Do not add unsupported HTTP request counts, URL paths, response codes, decrypted content, application latency or app-usage claims. UDP/443 remains UDP/443 without additional protocol evidence.

## 11. M6 — Validation and handoff

### Automated checks

Extend focused tests where behavior changes. Existing Vitest suites cover projections, viewport math, session state, gate/trace clients and Lab player transitions. Reuse their fixtures. Add browser coverage for actual interaction, not tests duplicating CSS or component structure.

- [x] Sessions: stable selection after refresh/filter, multiple active sources, unknown/fallback summaries, failed manifests and correct IDs in both launches.
- [x] Traffic: time/pixel conversion, bounds, same-second ordering, zoom anchor, repeated seeks, playback cleanup, live → past → live, session end and disconnect.
- [x] Traffic data: linked clip/ledger/evidence selection, virtualized reveal, capture gaps, non-overlapping totals and separate attribution/association confidence.
- [x] Lab: paths and node selection for accepted/held/rejected/DNS/inbound traces, derived timing, branch visibility and pan/zoom selection stability.
- [x] Lab control: observation/replay changes cannot mutate gate state; queue stays NOW; recording/unauthorized/offline/expired/in-flight cases disable actions correctly.
- [x] Compatibility: legacy redirects/time queries, controlled client, recorded bundle serialization, demo isolation and production dashboard behavior.

Run from the repository root:

```bash
pnpm --filter @infrareveal/debug-dashboard test
pnpm --filter @infrareveal/debug-dashboard lint
pnpm --filter @infrareveal/debug-dashboard build
```

If shared runtime/DTO/selectors change, also run `pnpm --filter @infrareveal/session-state test` and validate both consumers. At integration, run `pnpm test`, `pnpm lint` and `pnpm build` once. Run backend/network suites if their contracts change; this UI plan does not require reimplementing the original gateway work.

### Browser, accessibility and performance

- [x] Review all surfaces at 1280 × 800, 1440 × 900 and a larger monitor with active and recorded sources. Capture screenshots against study 03 and document intentional deviations.
- [x] Confirm Traffic's density, whole-second primary labels, integrated scrubber and dominant timeline; Lab's dominant graph and separate controls; Sessions' cohesive, more spacious styling.
- [x] Exercise keyboard scrubbing/playback, source/node selection, splitters, focus restoration and zoom. Form controls retain native behavior, icons have labels and statuses are not conveyed by color alone.
- [x] Test text zoom, reduced motion and narrow-screen fallback. Controls stay reachable without shrinking desktop text to phone size. Validation uses a 200% zoom-equivalent logical viewport; native text-only zoom and additional browsers are not claimed.
- [x] Profile a representative large recording and sustained live fixture. Record dataset size, hardware, seek responsiveness, frame behavior, DOM rows and memory. Dragging responds without waiting for network completion; rendering and cache/trace retention stay bounded.
- [x] Confirm the navigator does not fetch fine-resolution data for the entire recording and selected-detail requests do not grow without limit during scrubbing.
- [x] Check for console errors, duplicate subscriptions, stale playback loops and leaked state after repeatedly entering/leaving each tool.

### Final delivery

- [x] Update the debug-dashboard README with Sessions, Traffic and Lab workflows, shortcuts, secondary actions and data-quality meanings.
- [x] Preserve the original Proxy Lab validation record and link outstanding hardware acceptance instead of claiming it passed during UI work.
- [x] Update this plan's milestones with implementation paths and validation evidence. Revise the report for material, intentional design changes.
- [x] Remove report-only fixture assumptions from production UI paths. Retain the standalone report as a design reference.

The redesign is complete when all three surfaces use real session data, the approved layouts/interactions pass review, existing controls and export remain functional, and shared-runtime compatibility checks pass.
