# Production dashboard browser checks

From the repository root, start the synthetic gateway in one terminal:

```bash
node debug-dashboard/test-support/gateway-fixture.mjs
```

Build and serve the dashboard in another:

```bash
VITE_POCKETBASE_URL=http://127.0.0.1:8095 pnpm --filter @infrareveal/dashboard build
pnpm --filter @infrareveal/dashboard preview --host 127.0.0.1 --port 5188
```

Using Playwright CLI (or its installed wrapper):

```bash
playwright-cli open http://127.0.0.1:5188/map/live-session
playwright-cli run-code --filename dashboard/test-support/browser-workspace.js
playwright-cli run-code --filename dashboard/test-support/browser-map-drag.js
playwright-cli run-code --filename dashboard/test-support/browser-map-worker.js
playwright-cli run-code --filename dashboard/test-support/browser-workspace-demo.js
playwright-cli run-code --filename dashboard/test-support/browser-render-budget.js
```

The workspace check adds synthetic captured wire counters and mixed city/country/
unknown geography at the API boundary. It checks direction and location filtering,
shared totals and playhead, drag-to-expand, saved projection/theme/labels, system
appearance, and mobile layouts. Screenshots go to `output/playwright`; create that
directory before running. Use a fresh browser session for each complete run.
The demo check verifies that the map transport is visible, pause/seek work in
both views, returning preserves replay, and Go live explicitly resumes following. These checks do not replace a Pi/network soak test.
The render-budget check counts actual WebGL calls: traffic must draw while playing
and stop while paused or covered by the expanded timeline. It also checks that
Equal Earth does not load Mercator and the Pi preset does not load tiled geography.

The drag regression check runs on an Equal Earth map. It queues multiple pointer
moves and then releases or cancels the drag in the same browser task, verifying
that deferred React updates keep the final position without reading cleared state.

The worker check selects Mercator (Equal Earth uses bundled SVG geography), then
imports the emitted worker and waits for MapLibre initialization. It
catches missing production dependencies even when the map canvas and traffic
overlays render successfully. It requires the built app, since Vite's development
server can resolve dependencies absent from production assets. The worker check
does not require OpenFreeMap connectivity; visually checking tiles and labels does.

The MapLibre ESM worker must be imported with `?worker&url` so Vite bundles its
dependencies. A plain `?url` copies only the entry module and leaves its sibling
imports missing. The bundled `.js` also uses Nginx's standard JavaScript MIME type.

## Traffic animation regressions

With the same gateway fixture, run Vite instead of the production preview:

```bash
VITE_POCKETBASE_URL=http://127.0.0.1:8095 pnpm --filter @infrareveal/dashboard dev --host 127.0.0.1 --port 5188
playwright-cli open http://127.0.0.1:5188/map/live-session
playwright-cli run-code --filename dashboard/test-support/browser-rolling-animation.js
playwright-cli run-code --filename dashboard/test-support/browser-recorded-animation.js
playwright-cli run-code --filename dashboard/test-support/browser-traffic-shaders.js
playwright-cli run-code --filename dashboard/test-support/browser-mercator-cache.js
```

The test makes the fixture ephemeral with a one-minute retained window. It reads
the actual direct/traceroute layer clocks through multiple retention ticks, then
checks pause, window-relative seek, faster replay, expired-position clamping, and
return to live. GPU checks cover sample boundaries, long uptime, and phase wrapping
for direct, traceroute, and country streams. This requires Vite for module access.
It previously reproduced nine backward clock resets in seven seconds.

The recorded check crosses an activity-request boundary and checks uninterrupted
clocks, stream data, and GPU model identity. The shader check additionally follows
an isolated captured burst along each direction of direct, traceroute, and country
paths: it must remain visible in flight, not appear ahead or linger behind, finish
after arrival, and stay continuous as history buckets shift. The former
latest-rate-only renderer erased all 24 tested in-flight burst positions.

## Map performance and rendering detail

`browser-map-performance.js` instruments a production React build with readable
function names. Build with:

```bash
VITE_POCKETBASE_URL=http://127.0.0.1:8095 pnpm --filter @infrareveal/dashboard exec vite build --minify false --sourcemap
```

Run it against the preview and standard fixture. It measures eight-second samples
at 6× CPU throttling and checks that the sidebar and waveform do not follow every
animation frame, Equal Earth prepares no Mercator data, and unchanged Mercator
routes are not resampled. These are local browser measurements, not Pi FPS results.

Against Vite, `browser-map-quality.js` switches Full detail to Raspberry Pi at 2×
pixel density. It checks actual GPU mesh sizes, single-canvas Pi rendering and full-detail canvas resolutions, fresh
radius attributes after capture updates, cached basemap geometry, label alignment,
fresh geography at higher zoom, and preference persistence. Run playback
checks with the browser in front; background/occluded windows throttle rendering.

`mapPlaybackClock.test.ts` covers dropped paints, exact pause/seek, replay rate,
long uptime and live duration extension without React. `displayUpdates.test.ts`
checks that event bursts publish their latest state and unchanged collections
retain identity. The rolling browser check distinguishes clock jumps from real
paint delays and samples paused clocks without forcing continuous redraws.

The second-pass plan is in `docs/implementation-guides/map-performance-pass-2.txt`.
Actual display-Pi profiles use the same browser, resolution and quality setting;
record GPU renderer, draw count, frame cadence, long tasks and session size.

The Mercator cache check exercises GPU country picking, reuse across animation
paints, invalidation on camera/size/traffic changes, and resource release when
switching to full detail. The normal production build contains no probe hooks.

`browser-live-clock.js` uses an isolated browser with intercepted API responses;
it needs no gateway fixture server and never writes production records. Start a
production preview, navigate the test browser to its origin, then run the file.
It reproduces the Pi's moving manifest `startedAt`, checks the absolute paused
clock and Active now tracks across refreshes, and holds a 65-second outage to
verify that live following resumes while explicit pause remains respected.
This takes about 80 seconds. Its request interception is removed on completion.
