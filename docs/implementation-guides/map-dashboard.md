# Map dashboard

Open `/map/:sessionID` for a recording or live session, or `/demo` for the unattended
lab display. The left pane contains **Both / Downloaded / Sent**, directional totals,
and location or service lists. Teal means downloaded to participant devices; amber
means sent from them. Arrows and text identify direction as well as colour.
Selecting a location filters the map, totals and timeline together. Unknown
locations remain in the list and totals without an invented map point.
The location details panel shows directional totals, payload rate, destinations,
clients and contributing services. Search the service list or open a service to
inspect its traffic at that location. Closing service details returns to the
location panel; closing location details clears the location filter.

## Traffic and playback

The map groups captured traffic by client, service and destination binding. The
history selector loads one, five or thirty minutes around the playhead. Totals
cover that loaded interval up to the cursor; they are captured wire bytes, including
headers. A counter enters the total only when its entire source bucket has elapsed.
Connection lifetime counters and conntrack estimates do not contribute.

Expand the left pane to open the full-screen traffic timeline. Escape or **Back to
map** returns to the map; filters and the playhead survive the transition. Each lane is
an exact endpoint series. The default rolling five-minute view shows only lanes
with completed directional traffic in the window, newest first.
Lanes animate into their new positions when activity changes. Traffic in the
last thirty seconds stays emphasized; older flows fade gently but remain readable
throughout the window. Transitions always animate.
**All lanes** also reveals endpoints with no traffic in the window. Scrolling or
focusing a lane holds the window and order. **Follow live** returns to recent active traffic and resumes
playback while keeping the selected history window. Recordings offer
**Follow playhead** instead.

Select a row to inspect destination evidence, or click its chart to seek. Teal
download and amber upload flows use smooth envelopes with a shared square-root
rate scale. Clock-aligned averages keep old samples stable; the scale holds until
a new peak or **Fit scale**. Fine activity samples supply recent windows, with
coarse history as fallback. Missing capture is hatched, partial flows are dashed,
and measured silence has no flow.

Pause, seek and playback speed operate locally on the same session clock. Rolling
retention advances the earliest available position without rebasing the clock.
Only a playhead whose history has expired is moved forward. Demo mode follows the
live edge; opening the timeline makes replay controls available, and returning to
the map resumes live playback.

## Activity blocks

The **Activity** button opens paged service activity in the loaded history interval.
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

**Display settings** offers Equal Earth, Mercator, appearance and location labels. Preferences are saved in this browser.

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

Map history requests use one-second resolution; a smaller window around the
playhead retains the source resolution for activity shapes. The backend preserves
fine bins at partial edges. Requests move in thirty-second steps and are bounded
to thirty minutes, 4,000 chunks and 8 MiB per complete response. Dense recordings
may require a shorter history interval. Activity lists use separate bounded pages.

`MapPlaybackClock` owns playback without frame-driven React renders. The renderer
reads clock uniforms and requests at most thirty animation paints per second.
Hidden maps and expanded timelines do not run map animation. UI publication uses
250 ms; user actions are immediate. Geography and connection geometry are cached
independently of changing rates and totals. Mercator uses device-resolution graphics
and smooth curves without device-specific detail settings. Timeline rows remain
virtualized, while activity selection and the shared scale include every lane.

The debug dashboard uses the same activity contract. Raw flow, DNS and gate panels
appear only for recorded diagnostic profiles and require a PocketBase superuser
token. They are optional to ordinary map and activity playback.

See [browser checks](../../dashboard/test-support/README.md) and
[lab demo](lab-demo.md) for validation and hardware deployment.
