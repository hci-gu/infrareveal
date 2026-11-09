# Browser checks

Seed an isolated core database with `scripts/dev-data.sh`, then start its backend
on port 8091 with capture and routing disabled. The `Example` recording and one
empty live session exercise data-bearing and unavailable-capture views. Use a
disposable database, not production data.

Start both frontends with `VITE_POCKETBASE_URL=http://127.0.0.1:8091`, the dashboard
on port 5193 and debug dashboard on 5194. Open a named Playwright CLI session:

```sh
corepack pnpm dlx @playwright/cli -s=dashboard open http://127.0.0.1:5193 --headed
node dashboard/test-support/run.mjs browser-product-api dashboard
node dashboard/test-support/run.mjs browser-shared-filters dashboard
node dashboard/test-support/run.mjs browser-traffic-timeline dashboard
node dashboard/test-support/run.mjs browser-timeline-motion dashboard
```

`run.mjs` supplies origins, seeded session discovery, assertions and page-error
collection through `browser-harness.mjs`. It invokes Playwright CLI without adding
a second browser dependency to the dashboard. Override `DASHBOARD_ORIGIN`,
`DEBUG_DASHBOARD_ORIGIN` and `GATEWAY_ORIGIN` for other ports; `PLAYWRIGHT_CLI` can
point to an installed CLI or wrapper. Scenario modules export one async function
and should be run through this runner, rather than passed directly to `run-code`.

The checks cover:

- `browser-product-api`: real manifests, windows, revisions, recorded/live views,
  both projections, activity evidence, debug Lab navigation and stream cleanup.
- `browser-shared-filters`: matching search/history/activity/location membership
  and totals across maps, lists and lanes; shared sorting; independent inspection;
  preserving location and service details across projection switches; keyboard
  controls and mobile layout.
- `browser-traffic-timeline`: recorded flow shapes, five-minute defaults, seeking,
  hold/resume, both themes/projections, mobile layout, fullscreen settings and
  paused-live recovery. It runs 132 GPU shader assertions, including while the
  system motion preference is reduced.
- `browser-timeline-motion`: 135 synthetic endpoints using the production timeline,
  retained quiet history, activity promotion, CSS transitions, entry fading and
  focus stability. This fixture never writes to the backend.

Screenshots go to ignored `output/playwright/`. The product scenarios read actual
backend data and do not arm gateway controls or mutate sessions.

## Live animation measurements

Start a three-minute simulation in the isolated backend:

```sh
curl -X POST http://127.0.0.1:8091/api/infrareveal/simulation
```

Open the returned session's `/map/:sessionID` in the named browser. Choose Mercator
and keep the map visible for the map check; the timeline check opens its own view.

```sh
node dashboard/test-support/run.mjs check-map-playback dashboard
node dashboard/test-support/run.mjs check-timeline-animation dashboard
```

The map check measures real shader draw cadence and clock continuity during live
updates and replay, then checks pause and GPU behavior. The timeline check measures
a fixed timestamp across display frames and data-buffer boundaries at five-minute,
thirty-second and half-speed windows. It checks that pause and held history stay
stationary, and reports frame timing/long tasks. Run it in both projections. The
simulation removes its data when it expires; restart it if more time is needed.
Measurements depend on the browser, GPU and viewport, so compare like-for-like runs.

## Unit and integration coverage

`testdata/aggregate-window-v2.json` is the shared contract fixture. Runtime
continuity tests live in `packages/session-state/src/runtimeContinuity.test.tsx`
and cover retention, outages, recovery, late responses, capture clears and revision
coalescing. Dashboard tests cover byte conservation, geographic evidence,
filter/playhead boundaries, stable caches, uncapped connection projection, lane
virtualization and ordering. Renderer assertions target our geometry and shaders;
they do not duplicate third-party uniform-store internals.

Run `corepack pnpm test`, `corepack pnpm lint` and `corepack pnpm build` from the
repository root. The server's ordering/cursor checks run with
`go test ./timeline ./gateway` from `pocketbase`. Physical capture and NFQUEUE
controls require the separate procedures in `docs/validation`.
