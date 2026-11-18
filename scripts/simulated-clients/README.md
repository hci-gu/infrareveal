# Mac simulated clients

Generate real browser and HTTP traffic on the Mac while the Pi forwards and
observes it and the Windows PC displays the live dashboard. This is a standalone
tool: its package lock and dependencies are separate from the pnpm workspace.
It makes no changes to the dashboard, Pi services, firewall, Wi-Fi association,
DNS configuration or IP aliases.

## What is implemented

- Concurrent Chromium/Chrome browser contexts, each with separate cookies and
  storage; randomized page choices, scrolling, dwell times and quiet intervals.
- Paced downloads, polling and explicit POST uploads. All transfers use real
  sockets; no mock observations are submitted to the Pi.
- Weighted scenario profiles, a reproducible random seed, staggered starts and
  a fixed run duration. No client overlaps its own operations.
- macOS route/DNS preflight and default-route monitoring during a run.
- A separate source-IP experiment with source-bound DNS and HTTP requests.
- JSON/NDJSON evidence, per-client success/failure/latency, transferred bytes,
  observed protocols and Mac process-tree resource samples.
- Graceful Ctrl-C, bounded subprocesses, and loopback-only integration tests.

Ordinary runs share the Mac's network identity. Thirty browser contexts are
thirty activity schedules, not thirty Wi-Fi stations or thirty backend clients.
The source-IP probe is the next step toward distinct backend identities; full
source-bound browser sessions are not implemented. DHCP, radio contention,
power saving, WebRTC, persistent chat connections and adaptive video playback
are not emulated. The video-shaped profile downloads paced segments; it does
not measure playback quality. Browser HTTP/3 may occur naturally and is recorded
when reported by Chrome; it is not forced. The installed macOS curl may lack
HTTP/3 support (inspect `curl --version`).

## Install and preview

Node 22+, macOS curl and Google Chrome are sufficient for ordinary runs.
`dig` is also needed for the source-IP probe.

```bash
cd scripts/simulated-clients
npm ci
node cli.mjs plan --scenario scenarios/browsing.json --clients 5
```

`plan` is offline and starts no browser or traffic. It prints the exact profile
allocation and start offsets. Defaults are five clients, five minutes including
a 30-second ramp, and seed 42. A seed repeats random choices, not Internet timing
or the number of operations completed in a fixed period.

The default browser channel is installed Chrome. To use Playwright's bundled
Chromium, run `npx playwright install chromium` and pass `--channel chromium`.
`--headed` displays the automated browser. Tests do not use your normal Chrome
profile, cookies or tabs.

## First real run

Connect the Mac and Windows PC to Infrareveal. On Windows choose **Use this
device as display**; leave the Mac as a participant. The Pi needs its normal
Ethernet uplink and an active observation session. Keep VPNs, forwarding proxies
and alternate Internet paths disabled for the measurement.

```bash
node cli.mjs check --scenario scenarios/browsing.json --clients 1
node cli.mjs run --scenario scenarios/browsing.json \
  --clients 1 --duration 180 --ramp-seconds 0
```

`check` resolves the configured target hostnames and inspects routes. It requires
the Pi (`10.0.0.1` by default) as the Mac's primary DNS server and as the next hop
for a public route and every resolved target. Use `--gateway` for another Pi
address. Browser encrypted DNS and system proxies are disabled for this
deterministic profile. The harness uses the system DNS configuration; it never
changes it. Browser extensions/native-app background activity are not reproduced.

The route check runs again approximately every five seconds during `run` and
stops the workers if the default path changes. It is a polling check, not packet
containment: it cannot prove the route for every future subresource or prevent
brief leakage after a route change. Preflight rejects private/special-use target
addresses because InfraReveal's live observer excludes them. Downloading the
dashboard itself is not a forwarding/capture benchmark.

After confirming that one client is visible on the Windows display:

```bash
node cli.mjs run --scenario scenarios/browsing.json \
  --clients 5 --duration 600 --ramp-seconds 30
```

The public browsing scenario uses ordinary paced Wikipedia/SVT navigation. For
sustained 20–30-client load, use a controlled endpoint and the mixed template:

```bash
mkdir -p ../../output/client-simulator
cp scenarios/controlled-mix.json ../../output/client-simulator/my-mix.json
# Replace the .invalid URLs with your controlled public endpoints.
node cli.mjs plan --scenario ../../output/client-simulator/my-mix.json --clients 30
node cli.mjs run --scenario ../../output/client-simulator/my-mix.json \
  --clients 30 --duration 3600 --ramp-seconds 60
```

The template allocates 10 browsers, 6 segment downloaders, 6 pollers,
4 background pollers, 2 uploaders and 2 mostly-idle clients. Smaller client counts
use proportional allocation. Placeholder hosts are allowed by `plan` but rejected
by `check` and `run`. The upload endpoint must accept arbitrary binary POST bodies.
Transfer targets should return 2xx directly: curl redirects are reported as
failures rather than following to uncontrolled destinations. Browser navigation
follows redirects normally and loads the page's real resources.

Supported profile fields are shown in the examples. `pauseSeconds` and
`dwellSeconds` are [minimum, maximum] ranges. `rateBytesPerSecond` is a per-transfer
curl cap, not a browser or whole-run bandwidth cap. Curl workers start a new
process for each operation and do not preserve connections between operations;
browser contexts preserve their own state for the run. The browser goes to a
blank page during pauses, but persistent service workers may still do background
work. Include quiet intervals longer than 45 seconds when testing separate activity
blocks. Browser contexts share a Chrome process and are not separate OS stacks.

## Two-source-IP feasibility probe

First establish that two additional addresses are unused, within the participant
subnet and outside the active DHCP allocation. The repository's default DHCP
range is `10.0.0.50–150`; verify the actual configuration. Determine the Mac's
Wi-Fi interface from `check` output, rather than assuming it is `en0`.

For example, **only if `en0`, `.10` and `.11` are appropriate**:

```bash
sudo ifconfig en0 inet 10.0.0.10 netmask 255.255.255.255 alias
sudo ifconfig en0 inet 10.0.0.11 netmask 255.255.255.255 alias
node cli.mjs probe --url https://YOUR_CONTROLLED_HOST/small-file \
  --source-ips 10.0.0.10,10.0.0.11
sudo ifconfig en0 inet 10.0.0.10 -alias
sudo ifconfig en0 inet 10.0.0.11 -alias
```

Remove the aliases after the probe even if it fails. The tool itself does not
execute any `ifconfig` mutations. It refuses addresses absent from the selected
interface and makes three rounds of requests from each source IP:

1. Query the Pi's DNS server with `dig` explicitly bound to that source IP.
2. Use the returned A record with curl `--resolve`, preserving hostname, TLS
   certificate verification and SNI, and bind curl to the same source IP.
3. Record the actual local/remote address, status and timing. Redirects fail;
   choose a small endpoint returning 2xx directly.

A passing probe proves those source-bound round trips on the Mac. Inspect the
Pi's normal session/map data separately to verify both client IPs, bidirectional
traffic and DNS attribution. Both IPs still share one MAC and one Wi-Fi
association; no extra DHCP leases exist. Do not designate the Mac as a display
during the experiment. Full source-bound browser routing, including DNS and
QUIC semantics, is a follow-up after this feasibility check.

## Evidence and interpretation

Default output is `output/client-simulator/<timestamp>-<pid>/` at the repository
root. `--out` selects another **new** directory; existing evidence is never
overwritten.

| File | Contents |
| --- | --- |
| `plan.json` | Resolved run configuration, profiles, seed and start offsets |
| `preflight.json` | Platform, curl version, selected interface/addresses, routes and DNS |
| `events.ndjson` | Operation results, errors, start/stop events and resource samples |
| `summary.json` | Final per-client totals, latency percentiles and stop reason |

Browser latency is navigation to DOMContentLoaded, not full-page completion.
Curl timings include DNS, connect, TLS and first-byte phases. Percentiles use
the last 2048 completed operations per client. Browser byte estimates include
completed resource headers/bodies; curl counts transfer bodies. These are not
comparable to the Pi's packet/wire counters, and incomplete/cancelled transfers
can be missing. The reported Mbps is an application-level estimate, not a
measurement of Wi-Fi airtime or packet rate. HTTP failures, failed resources and
cancelled operations are reported separately.

Exit 0 means every scheduled client completed at least one successful operation,
with no failed top-level operations, and the requested duration elapsed. Browser
subresource failures do not force exit 1; inspect their counters. Exit 1 indicates
a configuration/runtime/workload failure; 130 means interrupted. A normal duration
cutoff may cancel an in-flight request without counting it as either a success or
a failure. A passing workload is not a Pi capacity pass.

Process-tree RSS/CPU includes browser and curl children. `ps` CPU is an estimate;
host free memory and load average are context rather than available-memory or
CPU-capacity guarantees. Watch these to detect a generator bottleneck. The tool
does not collect Pi metrics or query changing dashboard APIs; use the existing
Pi measurement tools alongside it and correlate UTC timestamps. Production
validation still needs Pi capture/drop/resource evidence and Windows UI checks.

## Local verification

```bash
npm test
npm run test:browser
```

The normal suite starts loopback HTTP/DNS fixtures and tests real curl downloads,
uploads, source binding, failure reporting and SIGINT cleanup. The browser suite
uses installed Chrome against a local page with subresources and checks isolated
cookies, repeat visits, byte/protocol reporting and shutdown. `--local-only` accepts
literal loopback URLs, blocks external browser HTTP/WebSocket requests, and marks
the run as development evidence. It does not validate the Pi or add IP aliases.
