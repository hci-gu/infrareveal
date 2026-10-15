# Map dashboard

Open `/map/:sessionID` for a recording or live session, or `/demo` for the unattended
lab display. The left pane contains **Both / Downloaded / Sent**, directional totals,
and location or service lists. Teal means downloaded to participant devices; amber
means sent from them. Arrows and text identify direction as well as colour.
Selecting a location filters the map, totals and timeline together. Unknown
locations remain in the list and totals without an invented map point.

## Traffic and playback

The map groups captured traffic by client, service and destination binding. The
history selector loads one, five or thirty minutes around the playhead. Totals
cover that loaded interval up to the cursor; they are captured wire bytes, including
headers. A counter enters the total only when its entire source bucket has elapsed.
Connection lifetime counters and conntrack estimates do not contribute.

Expand the left pane to open the full-screen traffic timeline. Escape or **Back to
map** returns to the map; filters and the playhead survive the transition. Rows group
by service, client and remote location. Select a row to inspect destination and
classification evidence, or click its chart to seek. Downloaded wire rate appears
above the baseline and sent wire rate below it. Missing or partial capture is
shown separately from measured quiet time.

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

## Geography and routes

**Display settings** offers Equal Earth, Mercator, appearance, location labels and
rendering quality. Preferences are saved in this browser.

- **Equal Earth** uses bundled Natural Earth geography, directional connections
  and paired linear volume bars. Its background works without a network connection.
- **Mercator** offers a detailed MapLibre basemap, route controls and directional
  columns with a fixed logarithmic scale. Its online tiles and fonts need internet
  access; Raspberry Pi mode uses bundled geography.
- **Automatic**, **Raspberry Pi** and **Full detail** control rendering cost.
  Automatic selects Pi detail on browsers reporting four or fewer logical CPUs.

Country-only evidence uses country footprints. City markers represent approximate
IP locations. Destinations without coordinates are still counted. Route evidence
is selected at the playhead for the exact destination/protocol/port/network binding;
expired or invalidated paths cannot reappear. Without intermediate evidence, the
direct line is an endpoint approximation. Service details show the evidence and,
for an active session, a control to request a bounded measurement.

Mercator's travelling bursts illustrate the recent captured payload shape over
four seconds. They do not alter measurement timestamps or totals. Reduced-motion
mode shows current volume without travelling history.

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
Hidden maps and expanded timelines do not animate. UI publication uses 250 ms in
Full detail and one second on Pi; user actions are immediate. Geography and route
geometry are cached independently of changing rates and totals. Pi mode uses one
WebGL canvas at one device pixel per CSS pixel and simpler curves.

The debug dashboard uses the same activity contract. Raw flow, DNS and gate panels
appear only for recorded diagnostic profiles and require a PocketBase superuser
token. They are optional to ordinary map and activity playback.

See [browser checks](../../dashboard/test-support/README.md) and
[lab demo](lab-demo.md) for validation and hardware deployment.
