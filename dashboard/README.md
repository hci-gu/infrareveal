# InfraReveal dashboard

The map reads the product API through `@infrareveal/session-state`. Open `/` for
sessions, `/map/:sessionID` for a recording or live session, and `/demo` for the
configured kiosk session. Vite uses `VITE_POCKETBASE_URL` to select the gateway;
position and map style overrides are documented in `.env.example`.

```sh
corepack pnpm install
corepack pnpm --filter @infrareveal/dashboard dev
```

Both Equal Earth and Mercator show service/client tracks, directional traffic,
unknown locations, country estimates and captured wire totals. Mercator keeps the
route/direct toggle, perspective controls and animated directional payload bursts.
The illustrated travel speed is not measured packet latency. Country estimates
remain footprints rather than precise endpoint pins; unknown hops remain gaps.

The manifest supplies immutable session start, retention floor, capture health,
policy and revision. One session revision stream invalidates bounded map windows.
The selected history is 1, 5 or 30 minutes; an adjacent fine window uses the
session's capture resolution (50 ms by default) for bursts. Cached windows support
local playback. Pausing freezes absolute time while live capture continues;
retention clamps only positions that have actually expired.

Every total comes from completed captured sample bins. No conntrack counters,
lifetime estimates or invented gap traffic are added. Coarser history bins retain
exact sums at their boundaries. Capture intervals distinguish observed silence,
partial capture and unavailable evidence. An unlocated endpoint still contributes
to totals. Shared IPs retain separate service, protocol, port and network bindings.

**Activity** opens a paged block browser. Blocks are inferred service activity
separated by quiet gaps, not proof of browsing attention. Details show original
and retained starts, active time, captured totals, confidence and capture quality.
Provisional blocks can change within the correction horizon. The service inspector
shows bounded attribution evidence and destination measurements, without
reconstructing individual connections.

Route publications appear only after their `available_ms` time. Selection uses the
exact session/IP/protocol/port/network epoch binding; expiration or network
invalidation cannot resurrect an older path. The inspector can request a new
measurement for a captured destination within the gateway's normal quota.

See [browser checks](test-support/README.md) for validation against the real API.
Unit tests cover byte conservation, directional bursts, route history, geographic
precision, playback clocks and renderer geometry. Run `corepack pnpm test`,
`corepack pnpm lint` and `corepack pnpm build` from this directory.
