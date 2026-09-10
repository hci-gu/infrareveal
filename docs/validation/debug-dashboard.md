# Dashboard browser validation

Use the [debug dashboard fixture instructions](../../debug-dashboard/README.md#validation-and-fixtures) to start the loopback gateway and development servers. Run `pnpm test`, `pnpm lint` and `pnpm build` from the repository root before browser review.

The fixture supplies recordings, multiple active sessions, partial capture, missing summaries, realtime events and simulated gate controls. These checks establish UI behavior; use the [Proxy Lab Pi procedure](proxy-lab-raspberry-pi.md) and [flow capture Pi procedure](flow-activity-raspberry-pi.md) for physical gateway acceptance.

## Browser scripts

The scripts in [test-support](../../debug-dashboard/test-support/) are Playwright CLI `run-code` functions. Run them against the development servers; performance and lifecycle instrumentation resolve Vite module URLs. The lifecycle check also needs the production dashboard on port 5175.

| Script | Coverage |
| --- | --- |
| `browser-acceptance.js` | Selected sources, playback, inspection, layout controls and simulated gate decisions |
| `browser-regressions.js` | Failed/offline data, compatibility routes, exports and control failure states |
| `browser-layouts.js` | Live/recorded desktop views, narrow screens and zoom-equivalent layout |
| `browser-performance.js` | Large recording, cold/warm seeking, frame time and bounded detail loading |
| `browser-lifecycle.js` | Sustained stream, route changes, subscription cleanup and production map smoke check |

Scripts reset their fixture sources; lifecycle scenarios also end and delete fixture sources. Store generated screenshots, logs and JSON results under `output/playwright/`, as the scripts do. Record the candidate commit, browser, viewport, build mode and fixture configuration with any results attached to a release or issue.

## Interaction and evidence checks

- Sessions: selection survives filtering/refresh; each launch uses the selected ID. Failed summaries do not block navigation. Empty, missing and offline states retain source identity.
- Traffic: scrubbing, keyboard shortcuts, five-second steps and zoom share one cursor. Native inputs retain their arrow behavior. Recordings have a fixed End; live history explicitly returns to following.
- Inspection: selecting a clip or record links the inspector and timeline. Window activity stays distinct from lifetime counters. Missing capture and missing audit remain unknown rather than zero.
- Lab: node selection, branches, zoom and fit preserve inspection state. Replay and requested configuration do not change effective armed policy. Recordings show durable audit; the live approval queue uses current server time during replay.
- Simulated controls: exercise flow, strict tuple and DNS modes; approve/reject, approve-all, accept-next, pause/resume, drain and disarm. Offline, unauthorized, expired, terminal and in-flight decisions are disabled or reconciled correctly. An unavailable queue is labeled unloaded.
- Compatibility: verify legacy session/time links, the controlled client, secondary treemap, utilities focus restoration and render-bundle download. Explicit demo mode makes no control requests.
- Export: preserve the selected recording ID, 1440 × 810 dimensions, 30 fps and full source timestamp precision regardless of interactive pane dimensions.

## Layout and accessibility

Review live and recorded Sessions, Traffic and Lab at 1280 × 800, 1440 × 900 and 1920 × 1080. Check 390 × 844 for the narrow layout and 720 × 450 for a 200%-zoom-equivalent layout. These viewport checks do not replace native browser zoom or cross-browser testing.

Verify no document-level horizontal overflow, readable transport labels and reachable optional panes. Exercise source selection, playback, splitters, node activation and dialog focus restoration by keyboard. Controls need accessible names; uncertainty and connection states need text as well as color. Reduced motion must preserve static direction, paths and selection.

## Performance and lifecycle

Use the large fixture with 10,000 flows and 8,000 DNS records. Measure overview load, both cold and warm seeks, frame-time percentiles and maximum gaps, rendered rows/DOM nodes, heap, request intervals, selected-flow counts and detail-cache usage. Cold detail projection has previously caused noticeable stalls, so do not report warm-only results. This fixture does not reproduce backend pagination or physical capture throughput.

The navigator must use coarse coverage while fine activity requests remain bounded by visible/selected ranges. Requests that become obsolete must be cancelled, selected evidence must retain its independent request owner, and detail-cache usage must stay within its configured budget.

During a sustained live stream and repeated Sessions → Traffic → Lab navigation:

- Check that trace retention stays within its time/count limits and DOM size remains bounded. Short runs do not establish a multi-hour memory plateau.
- Keep one active trace subscription; leaving Lab closes it, clears credentials/control state and stops its playback driver.
- Keep stream delivery gaps distinct from capture loss and gate-audit loss.
- End an active fixture source and verify fixed recording behavior; delete a selected fixture source and verify explicit missing-source states.
- Open and seek the same recording in the production map through the shared runtime. Confirm debug workspace styles and controls do not leak into it, and inspect browser errors.
