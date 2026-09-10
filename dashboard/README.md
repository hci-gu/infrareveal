# InfraReveal dashboard

Remotion-powered session map using the shared `@infrareveal/session-state` runtime.
The first map slice renders geolocated destinations and active route arcs for the
current Remotion frame. The same cursor logic works for recorded playback and a
live-following session.

The index at `/` lists the available sessions without loading timeline detail.
Selecting a session opens `/map/:sessionID`, where the route ID drives the shared
session-state controller. Direct map URLs and browser refreshes are supported by
the production Nginx fallback.

```sh
pnpm install
pnpm dev
```

The map uses a custom Night atlas style with token-free OpenFreeMap vector tiles,
subtle borders, geographic grid lines, and labels that reveal detail as you zoom.
Copy `.env.example`
to `.env.local` only when overriding the gateway position, label, or map style.

The map fills the viewport, with a compact mobile layout. The destination panel
can filter active endpoints and focus the map on an individual destination. Map
controls switch perspective, toggle traffic, zoom, fit the currently visible
network, and return to the gateway.

Connections remain thin one-pixel strips, including after traffic becomes idle.
Round, shaded 3D bulges travel along them; their radius uses a fixed compressed
scale of recent payload bytes per second, so small exchanges and sustained streams
remain visually distinct. Co-located endpoints are summed before sizing.

The map requests a bounded 90-second activity window at 500 ms LOD. Fine samples
are integrated into half-second display buckets, retaining short bursts; overlapping
LODs are not counted twice. Six seconds of history carry volume along the arcs.
Complete sparse buckets mean silence. Missing/partial coverage is marked, and
older sessions without samples use explicitly labeled average flow-byte estimates.
The inspector shows recent payload rate or the estimated average as appropriate.

Bulge movement is illustrative, not measured packet travel speed or direction.
The GPU mesh uses the Remotion frame clock and freezes when paused; reduced-motion
preferences hold the geometry still while allowing traffic measurements to update.
Traceroute paths remain approximate, and location is coarse IP geolocation.

The activity histogram counts overlapping geolocated flows, not throughput.
The custom player controls preserve seeking through the shared timeline cursor.
Space plays/pauses, left/right arrows move ten seconds, and the timeline slider
retains its native keyboard behavior. Playback supports 0.5×, 1×, 2×, and 4× speed.
For a live session, playback follows the live edge until the viewer pauses or
seeks backwards. The status changes to `Behind live`, and the `Go live` control
seeks to the moving edge and resumes playback. The shared transport also supports
gateways that still expose only PocketBase collection routes; those compatibility
queries remain bounded to the requested timeline window.
