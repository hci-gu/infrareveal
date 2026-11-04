# InfraReveal dashboard

The map reads the product API through `@infrareveal/session-state`. Open `/` for
sessions, `/map/:sessionID` for a recording or live session, and `/demo` for the
configured kiosk session. Vite uses `VITE_POCKETBASE_URL` to select the gateway;
position and map style overrides are documented in `.env.example`.

```sh
corepack pnpm install
corepack pnpm --filter @infrareveal/dashboard dev
```

To use the running Pi backend from the same Ethernet LAN, set
`VITE_POCKETBASE_URL=http://192.168.10.120:8090` in `.env.local` and restart Vite.
This connects to the Pi's PocketBase API directly; the frontend runs on your Mac.

Both Equal Earth and Mercator show service/client tracks, directional traffic,
unknown locations, country estimates and captured wire totals. Both views use direct
connections from the gateway to destination locations. All tracks between the same
locations share one arc, combining their traffic while keeping sent and downloaded
directions distinct. In Mercator, selecting a track highlights its shared arcs
without splitting them or removing the other contributors' traffic.
Selecting a location opens a details panel with directional totals, payload rate
and the contributing services. Service details stay scoped to that location;
closing them returns to the location panel. Country estimates and unlocated
traffic use the same panel, with geographic precision kept explicit.
Mercator offers perspective controls and animated directional payload bursts.
The illustrated travel speed is not measured packet latency. Country estimates
remain footprints rather than precise endpoint pins.

The manifest supplies immutable session start, retention floor, capture health,
policy and revision. One session revision stream invalidates bounded map windows.
The selected history is 1, 5 or 30 minutes; an adjacent fine window uses the
session's capture resolution (50 ms by default) for bursts. Cached windows support
local playback. Pausing freezes absolute time while live capture continues;
retention clamps only positions that have actually expired.

Live refreshes keep the last successful window visible while the replacement
loads, including after a transient failure. A small updating/error status marks
stale data; failed requests retry automatically. Displayed capture bounds belong
to the loaded snapshot. Retention removes expired samples immediately, and session
changes, capture clears, history-size changes and unrelated seeks do not borrow
the previous view. Initial loading and confirmed empty capture are distinct.

Live sessions default to **Latest activity** across locations, tracks, service
destinations and timeline lanes. Recency uses completed captured traffic bins up
to the playhead, respecting direction and location filters. **Traffic volume**
and **Name** remain available; recorded sessions retain their default ordering.
Lists reorder at most once per second. Scrolling or focusing a row holds the
current order; **Back to latest** resumes ordering and returns to the top.

Every total comes from completed captured sample bins. No conntrack counters,
lifetime estimates or invented gap traffic are added. Coarser history bins retain
exact sums at their boundaries. Capture intervals distinguish observed silence,
partial capture and unavailable evidence. An unlocated endpoint still contributes
to totals. Shared IPs retain separate service, protocol, port and network bindings.

The expanded traffic timeline gives each series its own lane, including distinct
endpoints and capture epochs within one service. In the recorded default order,
lanes keep their order as totals change. Clock-aligned buckets keep old bar heights stable while the live window
advances. All selected series share a scale that expands for new peaks and holds
through quieter updates and scrolling; **Fit scale** fits it to the current data.
Changing the time window or filters also refits the scale.

**Activity** opens a paged block browser. Blocks are inferred service activity
separated by quiet gaps, not proof of browsing attention. Details show original
and retained starts, active time, captured totals, confidence and capture quality.
Provisional blocks can change within the correction horizon. The service inspector
shows destination locations, providers and bounded attribution evidence.
Live Activity defaults to newest activity first, ordered by the backend before
pagination, so a recently updated older block also appears on the first page.
**Oldest first** remains available for chronological review.

See [browser checks](test-support/README.md) for validation against the real API.
Unit tests cover byte conservation, directional bursts, direct connections, geographic
precision, playback clocks and renderer geometry. Run `corepack pnpm test`,
`corepack pnpm lint` and `corepack pnpm build` from this directory.
