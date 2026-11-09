# Map dashboard

Open `/map/:sessionID` for a recording or live session, or `/demo` for the unattended
lab display. The left pane shows the time range as `HH:mm - HH:mm`, directional
totals, and a full-width **Locations / Tracks** selector above the sortable lists.
Teal means downloaded to participant devices; amber
means sent from them. Arrows and text identify direction as well as colour.
The top-right **Filters** button opens one drawer for search, history, an optional
**Only active now** toggle and location. The sort selector beside it controls
both sidebar lists and fullscreen lanes. These filters apply to the map, both sidebar lists, timeline lanes
and totals before rendering. Search matches service, hostname, client, IP, protocol
and location; separate words must all match. **History** sets how far back graphs
and totals go. With **Only active now** off, every endpoint with traffic in that
history appears; turning it on limits endpoints to those active within fifteen
seconds of the playhead while keeping their selected history. The default is
five minutes with the toggle off. Filters survive
projection changes, map/timeline transitions and returning to live playback.

Selecting a location or service opens details without changing these filters.
Use **Location** in the drawer to narrow the whole dashboard. Unknown locations
remain in the list and totals without an invented map point.
The location details panel shows directional totals, payload rate, destinations,
clients and contributing services. Open a service to inspect its traffic at that location. Closing service details returns to the
location panel; closing location details leaves global filters unchanged.

## Traffic and playback

The map groups captured traffic by client, service and destination binding. The
shared history selector loads thirty seconds, one, five or thirty minutes around
the playhead. Totals
cover the selected history up to the cursor; they are captured wire bytes, including
headers. A counter enters the total only when its entire source bucket has elapsed.
Connection lifetime counters and conntrack estimates do not contribute.

Use the expand button in the left pane to open the fullscreen traffic timeline. The lane ruler
starts at the top, with no separate title or playback toolbar. Escape or the
left pane's **Back to map** button returns to the map; on mobile the main header
provides that button. Filters and the playhead survive the transition. Each lane is
an exact endpoint series. The default rolling five-minute view shows only lanes
with completed directional traffic in the window, with recently active lanes first.
Ongoing lanes keep their relative order through gaps shorter than fifteen seconds.
New or returning lanes join the active group in latest-activity order, behind
ongoing lanes. Only fifteen seconds of silence demotes a lane, so sustained
activity rises naturally as quieter lanes move down. The top bar's **Latest
activity** sort uses the same rule. Lane transitions always animate; quiet flows
fade gently but remain readable throughout the five-minute window.
The timeline has no separate activity or history filter: its lanes are the same
filtered endpoints used everywhere else. Scrolling or focusing a lane holds the
window and order. Use the bottom player's **Live / Go live** button to return to
live traffic, or play/seek to resume following the playhead. These actions release
the browsing hold and keep all selected filters.

Select a row to inspect destination evidence, or click its chart to seek. Teal
download and amber upload flows share one baseline, with download bulges above
and upload bulges below it. Compact rows show the service, location/client and
totals; the endpoint address remains in the hover tooltip and inspector. The
flows use a shared square-root rate scale. Clock-aligned averages keep old samples
stable; resolution follows the selected window rather than changing as a new
session grows. The scale holds until
a new peak or a filter/window change. Fine activity samples supply recent windows, with
coarse history as fallback. Missing capture is hatched, partial flows are dashed,
and measured silence has no flow.

The bottom progress bar shows clock times from the available session start
to its end (or live edge), without a separate elapsed-time readout.
Pause, seek and playback speed operate locally on the same session clock. Rolling
retention advances the earliest available position without rebasing the clock.
Only a playhead whose history has expired is moved forward. Demo mode follows the
live edge; opening the timeline makes replay controls available, and returning to
the map resumes live playback.

## Activity blocks

The **Activity** button opens paged activity for services matching the shared
filters in the selected history interval, without a separate search control.
Seek or change the history length to browse another interval. A block shows client,
service, observed span, active time, directional bytes, classification
confidence and capture quality. Selecting it seeks to its beginning and loads its
destination evidence. A long block's detail request covers a bounded interval;
its full retained summary remains visible.

Blocks union payload-active buckets for one client/service and split at the pinned
quiet gap (45 seconds by default). Simultaneous services can overlap. ACK-only
traffic inside a block contributes bytes but does not extend its span; traffic
outside blocks remains in map totals. These are inferred periods of network
activity and do not measure browser focus, pages viewed or a person's attention.

## Geography and connections

**Display settings** offers Equal Earth, Mercator, appearance, location labels and
a fullscreen toggle. Appearance preferences are saved in this browser; fullscreen
follows the browser’s current state, including when you exit with Escape.

- **Equal Earth** uses bundled Natural Earth geography, directional connections
  and paired linear volume bars. Its background works without a network connection.
- **Mercator** offers a detailed MapLibre basemap, perspective controls and directional
  columns with a fixed logarithmic scale. Its online tiles and fonts need internet
  access. Both projections always use their full renderer.

Country-only evidence uses country footprints. City markers represent approximate
IP locations. Destinations without coordinates are still counted. Both projections
show direct connections from the gateway to destination locations. Mercator combines
all tracks between the same locations into one arc with separate sent and downloaded
flows. Selecting any contributing track highlights that shared arc; its volume
continues to include all contributors. Service details show location, provider and
classification evidence.

Mercator's travelling bursts illustrate the recent captured payload shape over
four seconds. They do not alter measurement timestamps or totals. Traffic and
camera transitions always animate, independently of system motion preferences.

## Data and rendering cost

The shared runtime reads the session manifest, map windows and activity blocks.
One coalesced session revision stream invalidates cached windows. Pages of a map
window are assembled before replacing the displayed data; an incomplete page set
is never published. The browser cache is bounded to twelve windows and an
estimated 12 MiB. Reconnection refetches the manifest and affected windows.

Map history requests overlap by an extra thirty seconds where the API limit
allows, so the shortest live history stays visible across request boundaries.
Buffered samples outside the selected history do not contribute to totals.
Map history requests use one-second resolution; a smaller window around the
playhead retains the source resolution for activity shapes. The backend preserves
fine bins at partial edges. Requests move in thirty-second steps and are bounded
to thirty minutes, 4,000 chunks and 8 MiB per complete response. Dense recordings
may require a shorter history interval. Activity lists use separate bounded pages.

`MapPlaybackClock` owns playback without frame-driven React renders. The renderer
reads clock uniforms and requests a paint on every display frame while playing.
Hidden maps and expanded timelines do not run map animation. UI publication uses
250 ms; user actions are immediate. Geography and connection geometry are cached
independently of changing rates and totals. Mercator uses device-resolution graphics
and smooth curves without device-specific detail settings. Timeline rows remain
virtualized, while activity selection and the shared scale include every lane.

The expanded timeline paints its viewport and playhead on every display frame
using that same clock, independently of React publications and incoming capture.
Buffered SVG geometry is cached per lane and transformed as time advances; unchanged
measurements retain their geometry across data refreshes. Pause, seek, playback
speed and held history all use this clock without adding another animation timer.

The implementation has one workspace shell in
`dashboard/src/map/MapWorkspaceView.tsx`. It owns the overview, timeline and
location/service inspectors, preserving inspection when projection changes.
`dashboard/src/rendering/` contains the projection adapters and Mercator animation
loop. `map.css` owns shared layout, theme tokens and responsive styles.

`mapTracks.ts` groups and sorts captured chunks once into a catalog. `mapModel.ts`
uses that catalog for geography; `mapWorkspace.ts` computes filtered series,
locations, tracks and totals in one pass. There is no renderer connection cutoff;
API response/cache bounds still apply. Traffic-profile caching depends on captured
samples, endpoint availability and time boundaries rather than changing overview
counters. Geometry remains stable when only rates change. `FlowArcLayer` owns the
fixed mesh and clock-driven shader; no alternate detail or clockless path remains.

The debug dashboard uses the same activity contract. Raw flow, DNS and gate panels
appear only for recorded diagnostic profiles and require a PocketBase superuser
token. They are optional to ordinary map and activity playback.

See [browser checks](../../dashboard/test-support/README.md) and
[lab demo](lab-demo.md) for validation and hardware deployment.
