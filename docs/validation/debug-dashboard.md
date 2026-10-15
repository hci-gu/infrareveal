# Dashboard browser validation

Run the workspace tests, lint and builds, then follow the
[real API browser check](../../dashboard/test-support/README.md). Both frontends
must use the rewritten backend and its isolated seeded database. The core profile
has seven collections; optional raw diagnostics are absent.

The smoke check covers recorded map playback, Equal Earth and Mercator, inferred
activity blocks and endpoint evidence, an empty live session with unavailable
capture, a paused live clock, the activity page and gateway Lab. It verifies that
session navigation keeps one revision subscription and releases it on exit, with
no retired collector requests or browser exceptions.

Review wire totals at sample boundaries, independent and ACK-only traffic,
shared IPs with different service bindings, repeated visits separated by quiet
gaps, retained/original block starts and capture quality. A route must appear only
after its publication time; expiration and network invalidation must not reveal an
older route. Unit fixtures cover these exact sample and route semantics.

Repeat the optional diagnostics check against an isolated diagnostics profile:
unauthenticated or invalid-token reads must fail; a disposable authenticated read
must show the seeded DNS record. Availability is distinct from gate audit quality.
The UI must say not recorded when diagnostics were absent, and must never show a
previous window's diagnostics as the currently selected window.

Check desktop and narrow layouts, keyboard seeking, named controls, reduced motion,
map pan/zoom and Lab node navigation. Store screenshots and logs only beneath
`output/playwright/`. Record browser, viewport, API profile and build mode with
results. The smoke check is not a sustained performance benchmark.

Use the [Pi capture procedure](flow-activity-raspberry-pi.md) and
[Proxy Lab Pi procedure](proxy-lab-raspberry-pi.md) for actual packet capture,
fail-open gate behavior, route measurements and device performance. The browser
smoke check deliberately does not arm or modify live network controls.
