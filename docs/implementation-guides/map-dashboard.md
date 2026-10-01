# Map dashboard

Open `/map/:sessionID` for a recording or live session, or `/demo` for the unattended
lab display. The compact left pane contains **Both / Downloaded / Sent**, directional
totals, and location or service lists. Teal means downloaded to the participant
devices; amber means sent from them. Arrows and text identify direction as well as
colour. Locations rank by the selected direction; selecting a location filters the
map, totals, playback mini-chart, and detailed timeline together. Unlocated traffic
remains available in the list and totals without an invented map point.

Drag the pane's right edge past the snap target and release, or use its expand
button, to open the full-screen traffic timeline. The handle also accepts Enter or
Right Arrow. Escape or **Back to map** returns to the map. Filters and the playhead
survive the transition. Timeline rows group by service, client, and remote location;
click a row's name to inspect its connections, or click/drag its chart to seek.
Choose a retained-window, 30-second, 5-minute, or 30-minute view and use Earlier/Later
to move through it. On narrow screens the expand button replaces dragging and the
timeline has its own compact direction controls.

The timeline plots **captured wire rate**, using interval averages from the existing
activity summaries. Downloaded traffic appears above the baseline and sent traffic
below it. Visible rows share the labelled rate scale; dashed outlines indicate
partial capture and gaps mean missing capture. Lifetime counters can supply marked
estimates for totals, but never create artificial rate waveforms. Totals accumulate
only to the playhead, within the retained window. These are network wire bytes,
not application payload sizes. Country-only IP evidence uses country footprints;
city markers are still approximate IP locations.

The header's **Display settings** button opens:

- **Equal Earth** (default): a flat, area-preserving world map with bundled Natural
  Earth geography, simplified directional connections, and paired linear bars.
  Its background needs no internet access or API key. Pan, zoom, fit the world,
  centre on the gateway, or use Fit track in an inspector.
- **Mercator**: the existing detailed MapLibre basemap, perspective, traceroute
  controls, and paired directional columns with a fixed logarithmic scale.
  Its external tiles/fonts still need internet access.
- **Dark / Light / System** appearance and location label visibility. Preferences
  are saved in this browser. Custom basemap style URLs keep their provider's style;
  the surrounding interface still follows the selected appearance.

The expanded timeline reuses the same player, capture summaries, and session
runtime. Rows are virtualized, and rolling-session retention applies in both views.
The player keeps a fixed session clock while the visible retained window advances;
cleanup does not rewind traffic animation. Only replay positions that expire are
clamped to the earliest retained time. Activity requests stay aligned to fixed
30-second boundaries, and the GPU phase wraps seamlessly to retain precision during
long uptime.
Mercator bursts carry the recent captured shape along their route over an
illustrative four seconds. A later quiet sample does not erase a burst midway;
rates and totals still report their original measurement times. Reduced-motion
mode shows current volume without travelling history.
In demo mode, opening the timeline exposes replay controls and permits pausing;
returning to the map resumes the live edge and hides playback controls again.
The settings modal does not change server capture or retention configuration.

See [browser checks](../../dashboard/test-support/README.md) for reproducible
production-build checks and [lab demo](lab-demo.md) for deployment and hardware testing.

## Raspberry Pi performance

Display settings include Automatic, Raspberry Pi, and Full detail. Automatic uses
Raspberry Pi detail on browsers reporting four or fewer logical CPU cores. This
uses a bundled country basemap and one WebGL canvas at one device pixel per CSS
pixel, 32 curve segments and four tube sides. Full detail retains online tiles,
160 segments and twelve tube sides. Pi mode omits decorative glow, blur and
specular shading; country precision, unknown route spans and all measurements
remain intact. Both projections and tiled geography load independently.

Mercator caches the Pi basemap as one locally drawn texture. Zooming refreshes a
padded region at higher resolution, while small pans reuse it. Country labels
remain separate and sharp. Only the current geography image is retained; changing
traffic does not rasterize coastlines or borders again.

`MapComposition` dispatches to Equal Earth and lazy-loaded Mercator components.
`MapPlaybackClock` owns wall-clock playback without frame-driven React renders.
The renderer reads clock uniforms directly and requests at most 30 animation
paints per second, independent of replay speed. Pause, seek, long uptime and
retention use the same absolute frame origin. Hidden maps and expanded timelines
do not animate. UI/data publication is 250 ms in Full detail and 1000 ms on Pi;
user actions are immediate. Streaming display notifications are coalesced, while
the shared store accepts every event and preserves unchanged collection arrays.

Equal Earth does not request detailed activity until an inspector or timeline
needs it. Its static SVG geography has a separate paint surface; both camera
transforms update together during drag. Route geometry, country paths and
waveforms retain caches across playhead totals. Rate changes invalidate tube
radii without rebuilding unchanged position attributes.

Destination summaries use storage-revision deltas every five seconds. Only changed
flows rebuild their prefix sums. The retention cutoff is applied at lookup time,
and expired chunks are evicted locally. The existing SSE connection delivers
deletions; a full snapshot every minute repairs missed deletes. Healthy session
realtime connections reconcile windows every ten seconds, falling back to the
existing two-second polling cadence when disconnected. Manual refresh and session
events still reconcile immediately.
