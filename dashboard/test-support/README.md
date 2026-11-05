# Browser checks against the product API

Seed an isolated core database with `scripts/dev-data.sh`, then start its backend
on port 8091 with capture and routing disabled. The example recording and one
empty live session exercise both data-bearing and unavailable-capture views.
Use a disposable database; never use production data for this procedure.

Start both frontends with `VITE_POCKETBASE_URL=http://127.0.0.1:8091`, the map on
port 5193 and debug dashboard on 5194. Open a browser with Playwright CLI and run:

```sh
playwright-cli open http://127.0.0.1:5193 --headed
playwright-cli run-code --filename dashboard/test-support/browser-product-api.js
playwright-cli run-code --filename dashboard/test-support/browser-traffic-timeline.js
playwright-cli run-code --filename dashboard/test-support/browser-timeline-motion.js
```

The script reads actual manifest, map, block and revision endpoints. It checks
recorded playback, both projections, block evidence, empty live capture, paused
live time, activity details, absent diagnostics, Lab navigation and stream cleanup.
It does not mutate sessions or arm gate controls. Change its three origin constants
if your ports differ. The check expects the seeded `Example` recording.

For optional diagnostics, start a second isolated database seeded with the
diagnostics profile and point the debug frontend at it. Open the example Activity
page, expand Optional diagnostics, select DNS, and verify an invalid administrator
token is rejected. Enter a disposable superuser token and load the selected window;
the seeded DNS record should appear. Keep tokens out of screenshots, logs and git.

`testdata/aggregate-window-v2.json` is the unit-test contract fixture. Browser
checks deliberately use the backend schema and query implementation rather than
mocking collection responses. Physical capture, NFQUEUE controls and sustained
device performance require the separate Pi validation procedures in `docs/validation`.

Live refresh regression tests mount the real shared hooks with delayed responses
in `src/map/runtimeContinuity.test.tsx`. They cover window rollovers, extended
outages, automatic recovery, retention, capture clears, late responses and revision
coalescing. `aggregateProjection.test.ts` checks newest-first ordering, direction,
location and playhead boundaries; `useLiveList.test.tsx` checks the update cadence,
scroll/focus stability and returning to the latest order. Run `corepack pnpm test`
from the repository root. The server's ordering and cursor checks run with
`go test ./timeline ./gateway` from `pocketbase`.

The traffic timeline browser check covers recorded flow rendering, window defaults,
keyboard seeking, holding/resuming, both projections, light/dark themes, mobile
layout, removal of rendering-detail controls and returning from paused live time.
It runs with the system motion preference set to reduce, verifies the production
traffic shaders on the GPU, and saves screenshots to `output/playwright/`. `MapTimeline.test.tsx` adds a
135-endpoint regression for activity filtering, virtualization and browsing
stability. Flow geometry tests verify shared scaling and gaps without invented
traffic across silence or missing capture.

The motion check mounts the production timeline with 135 synthetic endpoints in
the browser. It verifies the five-minute default, retained quiet history, actual
CSS transitions when activity promotes a lane, entry fading, animations with either system motion preference, and
stability while focused. Its fixture never writes to the backend.
