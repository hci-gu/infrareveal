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
playwright-cli run-code --filename dashboard/test-support/browser-map-worker.js
playwright-cli run-code --filename dashboard/test-support/browser-workspace-demo.js
```

The workspace check adds synthetic captured wire counters and mixed city/country/
unknown geography at the API boundary. It checks direction and location filtering,
shared totals and playhead, drag-to-expand, saved projection/theme/labels, system
appearance, and mobile layouts. Screenshots go to `output/playwright`; create that
directory before running. Use a fresh browser session for each complete run.
The demo check verifies that expanded replay stays paused and returning resumes
live following. These checks do not replace a Pi/network soak test.

The worker check selects Mercator (Equal Earth uses bundled SVG geography), then
imports the emitted worker and waits for MapLibre initialization. It
catches missing production dependencies even when the map canvas and traffic
overlays render successfully. It requires the built app, since Vite's development
server can resolve dependencies absent from production assets. The worker check
does not require OpenFreeMap connectivity; visually checking tiles and labels does.

The MapLibre ESM worker must be imported with `?worker&url` so Vite bundles its
dependencies. A plain `?url` copies only the entry module and leaves its sibling
imports missing. The bundled `.js` also uses Nginx's standard JavaScript MIME type.
