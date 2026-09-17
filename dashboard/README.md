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

The map fills the viewport, with a compact mobile layout. The overview lists
domain tracks using the same shared grouping as the debug dashboard. Every
supported hostname belongs to its registered-domain group for that client and
session. Explicit aliases in `pocketbase/observer/domain_groups.json` merge related
domains, such as oaistatic.com into chatgpt.com. Connections without usable hostname
evidence remain in Independent traffic. Timing and shared providers do not imply
membership, and idle gaps do not split groups. Infrastructure traffic uses the
debug dashboard's existing exclusion rules.

Every track retains its assigned color through playback, sorting and live updates.
Select a track to dim other routes and destination markers, and open the right-hand
inspector; select it again, close the panel, or press Escape inside it to clear focus.
The inspector includes all observed member connections, including unmapped ones,
with searchable/paginated sockets, hostnames, locations, counters, attribution,
activity-association evidence and completed route probes. Linked DNS is shown for
the loaded activity window. Connection totals are the reported flow counters;
recent payload rate covers mapped connections and marks partial/estimated values.
Replay only reveals flows and grouping evidence observed by the playhead.
On mobile, scroll the horizontal track list and open details as a sheet.

The track list supports site/client search and an active-only filter. Map
controls switch perspective, toggle traffic, zoom, fit the currently visible
network or selected track, and return to the gateway. The final frame is retained
when a recording ends, so track selection and inspection remain available.
The **Routes** toggle switches between traceroute paths (on by default) and a
simplified direct connection to each destination. Both views retain track colors,
selection, traffic volume and playback position; route details remain available
in the inspector. The separate **Traffic** toggle hides or shows flowing traffic.

Connections remain thin one-pixel strips, including after traffic becomes idle.
Round, shaded 3D bulges travel along them; their radius uses a fixed compressed
scale of recent payload bytes per second, so small exchanges and sustained streams
remain visually distinct. Co-located endpoints within a track are summed before
sizing. Different tracks sharing a location retain separate paths and volumes;
slightly different arc heights make these shared routes distinguishable.

The map requests a bounded 90-second activity window at 500 ms LOD. Fine samples
are integrated into half-second display buckets, retaining short bursts; overlapping
LODs are not counted twice. Tube width smoothly interpolates the two latest
completed buckets over 500 ms, including burst onset and decay to silence. This
visual smoothing adds up to one bucket of latency; numeric rates and totals are
unchanged. The travelling accent uses a continuous timeline clock independent
of bucket rollover.
Complete sparse buckets mean silence. Missing/partial coverage is marked, and
older sessions without samples use explicitly labeled average flow-byte estimates.
The inspector shows recent payload rate or the estimated average as appropriate.

Country-only GeoIP estimates use a hatched country footprint and a labeled country
total instead of a pin or column at the provider's centroid. Missing city names
(including whitespace-only names) identify country-level estimates. Their final
connection span fades into the footprint in both route modes. The country total
includes only destinations without a city estimate, grouped by country rather
than coordinates; it uses the same replay, capture and active-only filtering as
city columns. Click the footprint or country label for sent/received totals and
per-track inspection. City-level traffic in that country remains separate.
Country-only intermediate router estimates are omitted from the located hop
chain, with a gap marking the uncertain span. Country polygons are bundled locally
from Natural Earth; missing small territories retain a country label without a pin.

City-level destinations accumulate **sent + received bytes** in shaded 3D columns.
IPs sharing the same geolocation form one column, stacked in track colors. Track
selection dims the other sections without rescaling the stack. Labels show totals
at prominent locations; hover a section for the location's received/sent breakdown,
destination and connection counts, and the track's share. Columns remain when
flowing traffic or traceroute paths are hidden, and retain their totals after a
connection ends. The active-only filter limits the visible locations while keeping
all historical bytes for each visible destination IP.

Column height uses a fixed logarithmic scale, so tiny exchanges remain distinct
from large streams and a newly appearing stream cannot shrink other columns.
Compact `flow_activity_chunks` wire-byte summaries are loaded for the whole session,
separately from the sliding rate window. Completed chunk totals are exact capture
counters; growth within a chunk is interpolated up to its last observed packet.
Live totals refresh every five seconds using storage revisions, including late
writes to earlier chunks. Seeking recomputes totals at the playhead rather than
incrementing animation state. Missing capture history uses explicitly marked `≈`
flow-counter estimates interpolated over the connection lifetime; partial capture
is identified in the hover details. Captured wire totals include headers and can
differ from the conntrack counters in the overview/inspector. Router hops never
contribute to destination totals, and route splits cannot count a flow twice.

Bulge movement is illustrative, not measured packet travel speed or direction.
The GPU mesh uses the Remotion frame clock and freezes when paused; reduced-motion
preferences hold the geometry still while allowing traffic measurements to update.
Saved traceroutes shape each connection's path using the responding, geolocated
hops in TTL order. Small hollow markers identify intermediate routers. Unknown
`0,0` positions are omitted; dashed spans bridge unanswered or unlocated hops.
Consecutive hops sharing a location collapse to one map point, but every recorded
hop remains in the connection inspector with its address and gateway round-trip
time. Reaching the destination does not mean every intermediate hop is known.

Routes match the selected session, destination IP, port and protocol, and appear
only once their probe completes on the timeline. Connections without a matching
probe retain an approximate direct arc. A traced connection renders exclusively
as one ordered itinerary: gateway → router → router → destination. The strip and
3D volume share the same sampled geometry; neighboring tube rings join at routers
and taper only at the gateway and final destination. Traffic advances on one clock
with equal illustrative travel time per leg, so even a short local hop is visible
before the long-haul leg. Only complete matching itineraries share a volume bundle.
Paths remain
approximate: probes are gateway observations and locations use coarse IP geolocation.

The activity histogram counts overlapping geolocated flows, not throughput.
The custom player controls preserve seeking through the shared timeline cursor.
Space plays/pauses, left/right arrows move ten seconds, and the timeline slider
retains its native keyboard behavior. Playback supports 0.5×, 1×, 2×, and 4× speed.
For a live session, playback follows the live edge until the viewer pauses or
seeks backwards or selects a speed other than 1×. The status changes to `Behind live`, and the `Go live` control
seeks to the moving edge and resumes playback at 1×. Map data updates arrive
through a separate React context, keeping Remotion’s video configuration stable
so refreshing observations does not restart its playback scheduler. The shared transport also supports
gateways that still expose only PocketBase collection routes; those compatibility
queries remain bounded to the requested timeline window.

Animation regression checks use the actual WebGL shaders for direct and traceroute
paths in both directions. Additional layer classes can be passed to the check. With the Vite dev server running, execute
`await (await import('/scripts/check-traffic-animation.js')).checkTrafficAnimation()`
in its browser console. `passed` must be `true`. The full live/playback check can
also run through Playwright CLI with an active session open:

```sh
playwright-cli run-code "$(cat dashboard/scripts/check-map-playback.js)"
```

Run that command from the repository root. It checks live speed restoration,
clock continuity while following and replaying, pause behavior, and GPU bucket
boundaries. It changes only the local playback controls and returns to Live.
