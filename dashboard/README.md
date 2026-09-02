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

The map uses a token-free OpenFreeMap/MapLibre base style. Copy `.env.example`
to `.env.local` only when overriding the gateway position, label, or map style.

The player controls are intentional: seeking changes the shared timeline cursor.
For a live session, playback follows the live edge until the viewer pauses or
seeks backwards. The status changes to `Behind live`, and the `Go live` control
seeks to the moving edge and resumes playback. The shared transport also supports
gateways that still expose only PocketBase collection routes; those compatibility
queries remain bounded to the requested timeline window.
