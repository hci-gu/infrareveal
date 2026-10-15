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
