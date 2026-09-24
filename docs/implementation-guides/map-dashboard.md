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
In demo mode, opening the timeline exposes replay controls and permits pausing;
returning to the map resumes the live edge and hides playback controls again.
The settings modal does not change server capture or retention configuration.

See [browser checks](../../dashboard/test-support/README.md) for reproducible
production-build checks and [lab demo](lab-demo.md) for deployment and hardware testing.
