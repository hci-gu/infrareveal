# InfraReveal debug workspace

Three independent session tools share the existing gateway data runtime. The [approved design](../redesign-report.html) and [implementation plan](../implementation-plan.md) describe the redesign. The production `dashboard` remains a separate application.

## Run locally

From the repository root:

```sh
pnpm install
VITE_POCKETBASE_URL=http://localhost:8090 pnpm --filter @infrareveal/debug-dashboard dev
```

`VITE_POCKETBASE_URL` is the gateway origin. Without it, the client uses the browser's hostname on port 8090. Configure a local environment file if needed; operator tokens belong in Lab's in-memory control panel.

## Sessions

The source browser lists all sessions, including multiple active sessions. Search by name, ID or displayed date; filter Live or Recordings. Select a source and use **Open Traffic** or **Open Lab**. Arrow keys on a source name move selection; links retain normal browser behavior.

Summaries load for visible and selected rows with at most three concurrent requests. A failed summary does not hide the source. Missing totals and collection-fallback totals show unavailable values; unspecified gate-audit completeness stays unknown. Active duration uses synchronized server time. Filtering and refresh retain the selected source, and a deleted selection is identified explicitly.

## Traffic

The timeline is the main working surface. Client-specific activity groups require supported associations; independent traffic preserves its socket identity. DNS, hostname attribution and activity association keep separate source records.

**Track importance** starts with **Session data**: groups and their connections sort by received + sent lifetime bytes, and larger connections get taller, more prominent tracks. **Recent data · 30s** instead ranks captured payload in the 30 seconds before the playhead; replay and scrubbing update it once per second. Recent ranking loads all flows in that bounded interval, independently of visible rows. Incomplete capture is marked with `+`; unknown values stay unknown. **Size contrast** adjusts the height difference (0–100%); a square-root scale preserves small connections. **Equal tracks** restores uniform heights and the original order. The time axis continues to represent connection duration. These preferences are saved with the session layout.

The tracks contain mirrored payload-rate curves: received traffic above the center line, sent traffic below. Both directions and all loaded tracks share one linear bytes-per-second domain, shown above the timeline; each waveform's top/bottom represents that limit even when importance changes its track height. Epoch-aligned averaging adapts to zoom and loaded sample resolution. Hover a point for the interval's receive/send rates, or focus a connection for its busiest interval. Curves before the playhead are brighter. Unknown capture breaks the curve, incomplete observations use dashed outlines, and packet-only observations do not create payload spikes. Empty detail is labeled separately from observed zero payload.

For recorded sessions, completed requests covering a connection's entire lifetime also compare captured wire bytes with its final directional flow counters. A large shortfall (more than half and at least 64 KiB) marks the track and inspector **Activity detail incomplete**, overriding a misleading complete-window status. Partial or loading history is not classified as loss. Selecting a short connection loads its full evidence history, bounded to 15 minutes. This catches recordings affected by the former Linux BPF snapshot-length bug without inventing traffic from lifetime totals; those missing samples require a new recording after the collector update.

The single navigator below the tracks combines playback, the full-session range and the visible-window outline. Drag its handle, click/drag the ruler or use the step controls. Window zoom centers on the cursor. During playback the window advances in five-second steps while the playhead moves, avoiding repeated rendering of unchanged evidence. Earlier/Later and Shift + wheel pan time independently of vertical track scrolling.

| Action | Shortcut/control |
| --- | --- |
| Play / pause | Space outside form controls |
| Step one second | Left / Right arrow |
| Step five seconds | Shift + Left / Right, or −5s / +5s |
| Inspect evidence | Select a clip, marker or ledger record |
| Resize a pane | Drag its divider, or focus the divider and use arrows |
| Resume live following | Go live |
| End of a recording | End |
| Leave expanded workspace | Escape |

Scrubbing live history pauses the view while recording and the server clock continue. Recordings have a fixed end. Primary timestamps display whole seconds; raw JSON, correlation, sorting and render bundles preserve full precision.

Events, DNS and Flow records are sortable, virtualized views of loaded evidence. The inspector separates lifetime counters from whole captured buckets inside the visible window. Receive/send activity uses decoded payload bins; it does not distribute cumulative bytes across a clip. If finer chunks cover only part of a larger aggregate, the complete coarser observation is retained to avoid losing or double-counting its remaining data.

**More → Traffic utilities** contains the secondary treemap, restore layout, controlled client, render-bundle download and existing confirmed data-clear action. Export freezes the loaded recorded scene at the existing 1440 × 810 render dimensions. Pane geometry does not affect export dimensions.

Layout, filters, selected flow, cursor and track scroll are saved locally under `infrareveal.debug.v3.traffic.*`. Smaller windows initially close optional panes; selecting a record can open the inspector over the timeline.

## Lab

Lab is a node canvas with its own layout and controls. Select a trace by client, endpoint or protocol, then inspect nodes or use **Previous / Next stage**. The source-event selector distinguishes a queued event from its later verdict. A held event's path ends at its gate; a rejected event takes the drop path. Inbound and local DNS paths remain available.

Drag the canvas background to pan. Arrow keys on the canvas pan; node buttons support keyboard focus and activation. Zoom, Fit path, Reset view and expand controls affect only graph geometry. Observation branches can be hidden. Passive capture, attribution, enrichment, route probing and durable storage sit alongside forwarding.

**Replay & event inspection** contains slow motion, playback, event jumps, frame steps and a subordinate position slider. Event timestamps are source evidence; intermediate node transitions and connector geometry are explanatory rather than measured hop latency. Reduced motion keeps paths and selection visible without moving tokens.

**Live observe / Replay** changes the observation view. **Gate setup & controls** separately selects flow admission, strict packet stepping or DNS control and performs an explicit authenticated arm action. Effective policy always comes from the gateway's status. Strict mode retains the exact client/protocol/ports/remote tuple and watchdog constraints.

The approval queue is labeled **NOW**. Its polling and deadlines use the current synchronized server clock, even during historical replay. Approve/reject, approve all, strict accept-next, pause/resume, drain and disarm use the existing contracts. Offline, unauthorized, expired, terminal and in-flight decisions are disabled. Conflicts reconcile with the gateway. Recordings show durable audit instead of current decision controls.

Graph/filter/trace preferences use separate `infrareveal.debug.v3.lab.*` keys. Credentials, pending decisions and assumed armed state are never persisted. Leaving Lab cancels its requests and trace subscription and clears its control state.

## Evidence quality

- **Complete capture:** a loaded completeness window reports no known capture loss. Sparse absence of samples can represent silence within that coverage.
- **Partial / unavailable capture:** hatching and text identify dropped activity, disabled capture or capture errors. Missing samples are not counted as zero traffic.
- **Unknown / unloaded:** no completeness report covers the selected interval.
- **Browser trace loss:** delivery to Lab's live visualization was incomplete; durable capture can still be complete.
- **Gate-audit loss:** durable decision history is incomplete. This is separate from capture and browser delivery.
- **Hostname vs association:** attribution identifies a candidate hostname; association proposes a parent activity. Confidence and provenance remain separate.
- **Route probe:** a gateway approximation, not the client's application path or application latency.

## Validation and fixtures

Run `pnpm test`, `pnpm lint` and `pnpm build` from the repository root to check both consumers and shared session state. [Validation evidence](../docs/validation/debug-ui/validation.md) records browser scenarios and performance measurements.

For a local gateway substitute, in separate terminals:

```sh
node debug-dashboard/test-support/gateway-fixture.mjs
VITE_POCKETBASE_URL=http://127.0.0.1:8095 pnpm --filter @infrareveal/debug-dashboard dev --host 127.0.0.1 --port 5174
```

The fixture binds only to loopback and is never imported by the application. It supplies recordings, multiple live sources, partial capture, unknown summaries, SSE, and simulated gate contracts. Its deliberately public test token is `fixture-operator`. `POST /__fixture` configures dataset size, delay, disconnection, failed summaries, current decisions, trace gaps or source termination; `GET /__fixture` returns request diagnostics. It cannot control a gateway.

The `test-support/browser-*.js` files are Playwright CLI `run-code` functions, not production entry points. With a CLI browser session open, for example:

```sh
playwright-cli --session implementation run-code "$(cat debug-dashboard/test-support/browser-acceptance.js)"
```

The explicit development demo remains `/proxy-lab/demo?demo=1`; it never sends real gate mutations. Legacy bare `/timeline` and `/proxy-lab` routes retain `session` and `at` query handling. `/controlled-client` remains available.

Original gateway implementation and outstanding physical Raspberry Pi acceptance are preserved in [the earlier Proxy Lab plan](../docs/implementation-plans/proxy-lab-original.md). Local UI fixture checks do not claim physical gateway validation.


The lifecycle browser check also uses the production dashboard on port 5175:

```sh
VITE_POCKETBASE_URL=http://127.0.0.1:8095 pnpm --filter @infrareveal/dashboard dev --host 127.0.0.1 --port 5175
```

Browser scripts reset their local fixture sources with `resetSources`; lifecycle scenarios then end and delete a fixture source. Performance/lifecycle instrumentation resolves the loaded Vite module URLs, so run those checks against development servers. No real gateway mutations are part of this validation workflow.
