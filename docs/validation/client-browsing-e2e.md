# Physical client browsing test

Use a second Raspberry Pi to browse real public websites through the gateway's
`Infrareveal` access point. The test checks the resulting map data and service
activity blocks through the same APIs used by the dashboards.

## Run

The configured client is `pi@192.168.10.139`; the gateway is
`pi@192.168.10.120`. Run from this repository on a machine with Bash, Python 3,
SSH and SCP:

```bash
bash scripts/test-client-browsing.sh
```

SSH prompts for each host's password unless keys are configured. Passwords are
not saved. Optional arguments are the client, gateway and a new artifact directory:

```bash
bash scripts/test-client-browsing.sh pi@192.168.10.139 pi@192.168.10.120 \
  output/pocketbase-restructuring/client-e2e/my-run
```

Expect roughly six minutes, including the final 60-second settling period.
Progress appears in the output directory's `client.log`. Exit status zero means
all browser and gateway assertions passed; a website error, missing traffic,
capture gap or incorrectly merged revisit fails the run. No scheduled service
or continuous traffic generator is installed.

## Prerequisites

- Keep both Pis reachable over Ethernet. The client needs passwordless `sudo`
  and an idle, unaddressed `wlan0` supporting network namespaces. The runner
  refuses to take over a connected radio.
- The client needs Chromium, its matching ChromeDriver, Python Selenium,
  `iproute2`, `iw`, `wpa_supplicant`, `isc-dhcp-client` and `util-linux`.
  On the inspected Bullseye client the browser package names are
  `chromium-browser`, `chromium-chromedriver` and `python3-selenium`.
- The gateway needs one active session with healthy capture and Python 3.
  Its API stays on loopback; validation runs over SSH on the gateway.
- Both Pis' clocks must be synchronized. The suite assumes the repository's
  default open SSID `Infrareveal`, participant subnet `10.0.0.0/24`, 45-second
  activity quiet gap and 30-minute demo retention. GeoIP context is required.

The client at `.139` was prepared with Chromium/ChromeDriver
`126.0.6478.164-rpt1` and the distribution's Selenium package. Its Bullseye
ARMv7 userspace and OS were retained. Browser packages came from its signed
Raspberry Pi/Raspbian repositories.

## Scenario and assertions

Edit [the scenario](../../testdata/browsing-session.json) to change pages or dwell
times. The default sequence is:

1. Open three SVT news pages, spending 40 seconds scrolling on each.
2. Open two Swedish Wikipedia articles, spending 25 seconds on each.
3. Close the browser and remain quiet for 65 seconds.
4. Reopen SVT for 30 seconds in a fresh browser profile.

Each visit uses a disposable Chromium profile. Each page must return an HTTP
success/redirect status, finish on the expected domain and display body text.
The browser uses normal certificate checks and performs no logins or submissions.
Screenshots and a timestamped page journal, including the actual server IP for
each main document, are saved on the client.

The runner moves the physical Wi-Fi radio into a temporary network namespace,
joins the real AP and obtains a DHCP lease. Only loopback and Wi-Fi exist in
the browser's namespace; its route and DNS must use `10.0.0.1`. Checks also
require the participant to be unable to reach the PocketBase port and admin
dashboards. Ethernet continues carrying SSH outside the namespace.

The gateway verifier waits for normal classification and quiet-gap timers,
then requires:

- The original active session and capture epoch are unchanged.
- Capture covers the complete browsing interval with no reported packet drops.
- The actual client IP has bidirectional traffic for each visit, plus
  corresponding nonempty activity blocks. SVT must be classified as `svt.se`.
- Wikipedia may instead remain an independent endpoint when shared IPs produce
  conflicting DNS evidence. Such traffic must match the browser's actual server
  IP and carry `ambiguous_dns` evidence with the ambiguity flag. Arbitrary
  unclassified traffic cannot satisfy this check. The result reports how many
  received bytes were ambiguous rather than service-attributed.
- The two SVT visits have different activity block IDs.
- At least one destination used by this client has country context in the map
  API.

Browser dwell time is known test input. Activity blocks describe observed
traffic and can be shorter or split by quiet periods; they do not measure
attention. The suite tests the map API, not pixel rendering or complete route
discovery. It does not establish long-term USB adapter stability or physical
admin Wi-Fi client connectivity.

## Evidence and cleanup

By default artifacts go under
`output/pocketbase-restructuring/client-e2e/<UTC time>-<process ID>/`:

- `client/`: browser journal, six page screenshots, route/interface evidence,
  DHCP and Wi-Fi logs.
- `gateway/`: session manifest, map chunks, activity blocks and `result.json`.
- `gateway-before.json`, `client.log`, `verification.log`: run context and logs.

Copies remain under `~/infrareveal-e2e/results/` on each Pi. These bounded runs
do not remove earlier evidence automatically. Rolling sessions expire traffic
after their normal retention period; copy artifacts to preserve test evidence.

On completion or ordinary termination, the runner closes Chromium, stops its
private DHCP/Wi-Fi processes, returns the radio to the host and restores its
original interface state. A run is capped at 15 minutes. No persistent Wi-Fi
profile, host default route or gateway configuration is changed.

The verifier's offline rejection checks can run without either Pi:

```bash
python3 scripts/test-client-browsing-checks.py
```

These checks ensure unrelated clients, unsupported attribution, failed pages,
capture gaps/drops, an available Ethernet interface and merged revisits cannot
produce a passing result. A separate shared-endpoint case rejects an incorrect
server IP, missing ambiguity evidence or an unapproved scenario exception.

The harness also works with the single-radio proxy-only deployment: it snapshots
the active session manifest directly, so `DEMO_MODE` can remain disabled and no
dashboard or admin radio is required. Offline checks cover session/epoch changes
and complete, consistent pagination, including destinations on later map pages.

## Verified on 15 October 2026

The complete controller command passed against the deployed `data-refactor`
gateway. Chromium loaded all six pages with HTTP 200 through physical Wi-Fi at
`10.0.0.106`. The gateway recorded 5,285,588 wire bytes across 65 chunks and 16
activity blocks, with eight mapped destinations and complete capture coverage
without reported drops. The initial SVT visit and return had distinct blocks.
Most Wikipedia traffic carried explicit shared-IP ambiguity, matching the
server IP recorded by Chromium; it was not misreported as certain attribution.

Participant access to all three checked management endpoints was blocked.
Both dashboard views displayed the traffic without browser console errors.
After the run, no Chromium processes or test namespaces remained; `wlan0` was
unaddressed and disconnected again, and the Ethernet management route was
unchanged. All five offline verifier tests passed.

Local evidence is under
`output/pocketbase-restructuring/client-e2e-2026-10-15/validated/`, including
`gateway/result.json` and `client-cleanup.json`. Dashboard screenshots are
`output/playwright/client-e2e-map.png` and
`output/playwright/client-e2e-debug.png`.
