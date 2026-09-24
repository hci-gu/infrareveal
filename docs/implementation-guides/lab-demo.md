# Unattended lab demo

The Pi runs the gateway and dashboard; a separate screen PC joins `Infrareveal-admin`
and opens **http://10.77.0.1/demo**. Visitors join the participant SSID (`Infrareveal`
by default). The existing two-radio networking setup excludes admin traffic from
observation. The Pi needs its Ethernet uplink for visitor internet access and the
map's internet-hosted tiles/fonts.

## Enable

Use the [Pi deployment guide](pi-deployment.md) to back up the stopped database and
update the existing installation. Keep its `.env`, `data`, and `geoip` directories.
Add these settings to `.env`:

```dotenv
DEMO_MODE=true
DEMO_RETENTION_MINUTES=30
DEMO_DOMAIN_CATALOGUE=true
```

Then, from the repository on the Pi:

```bash
sudo bash scripts/build-pi-images.sh
sudo docker compose up -d --no-build --force-recreate
sudo docker compose logs --tail=100 proxy dashboard
```

Migrations run automatically. Demo mode creates one dedicated `Lab demo` session
and resumes the same ID after restart. Other active sessions are closed, preserving
their remaining data. Starting another active session is refused while demo mode
is enabled. This avoids accidentally redirecting capture away from the display.
No existing recording is converted into the demo session.

The demo uses an ephemeral session with a configurable rolling window. Choose
1–1440 minutes. The startup environment sets the demo's retention each restart;
PocketBase's `sessions.retention_minutes` also allows a live adjustment. Existing
five-minute ephemeral sessions retain their previous setting. A zero/unset value
on an ordinary ephemeral session means the legacy five-minute default.

Every 15 seconds the gateway aggregates domain evidence, then expires observations
in the same transaction. Live connections and the DNS/route anchors they need stay
available even if they started before the window. Both dashboards take retention
from the server manifest and evict browser entities, indexes, and detail caches.
Shrinking a window deletes older data; expanding it cannot restore deleted data.
SQLite reuses freed pages, so file size can remain at its previous high-water mark.
Retained traffic still depends on load and concurrent connections.

To leave demo mode, set `DEMO_MODE=false` and recreate the containers. The `/demo`
page then shows that demo mode is disabled. The existing session remains ephemeral
until you disable its `ephemeral` setting and clear `active` in PocketBase; this
lets you choose whether to continue rolling capture or close the retained window.
Set `DEMO_DOMAIN_CATALOGUE=false` to stop permanent aggregation independently.

## Display PC

1. Save the `Infrareveal-admin` Wi-Fi connection for automatic reconnect.
2. Disable sleep, hibernation, and screen blanking while plugged in.
3. Copy `scripts/demo-kiosk.py` to the display PC, install Python 3 and Chromium,
   and run it at desktop login:
   `python3 /path/to/demo-kiosk.py --url http://10.77.0.1`.
   Use `--browser /path/to/browser` if it cannot find Chromium/Chrome/Edge.
   The launcher waits for the API **and dashboard HTML** before opening the browser,
   uses its own profile, relaunches after browser exit, and reloads after a sustained
   gateway outage. Keep it running for unattended recovery. A browser URL alone
   cannot retry the initial load if the Pi is off before any dashboard code loads.
   On Linux, a desktop autostart entry can run the command; on Windows/macOS use
   the equivalent login task and supply the browser executable path as needed.
4. Reboot the PC once with the Pi initially off, then turn the Pi on. The display
   should recover without clicking Retry.

The demo URL automatically selects the designated session, follows the live edge,
hides playback controls, and shows the participant SSID and retained duration.
It retries initial failures and session replacement. Gateway, capture, and cleanup
problems are visible on the screen; an idle network is allowed to show an empty map.
Normal `/map/:sessionID` pages retain interactive playback and timeline controls.
The screen does not generate synthetic visitor traffic.

## Permanent domain catalogue

Open **http://10.77.0.1/_/** and sign in as a PocketBase superuser. Review the
`domain_catalogue` collection. It is available only to superusers through the API.
Each registered domain has:

- first/last observed timestamps;
- DNS query count and distinct attributed-flow counts split by confidence;
- up to 16 hostname examples and 16 observed query-to-CNAME examples;
- `review_status` (`pending`, `approved`, `rejected`), `proposed_group`, and notes.

DNS counts include queried names whether or not a connection follows. They are not
counts of visits or users. Flow counts count attribution records, not packet samples;
when a retained attribution changes domain/confidence, its count is transferred.
Expired observations keep their final aggregate contribution. Low-confidence names
are listed separately and cannot establish a group membership by themselves.
The catalogue collects only from the dedicated demo session, including its still-
retained evidence when aggregation is enabled. It cannot recover already expired data.

The permanent collection has no client IP, MAC, session ID, flow ID, or traffic
history. A temporary checkpoint table deduplicates source revisions transactionally
and is pruned with source records. Concurrent DNS updates, restarts, and transaction
rollback do not double-count. Examples are bounded per domain; discovering new
registered domains still grows the catalogue. Operator review fields are preserved
when counts update. If aggregation fails, cleanup is deferred and the display warns;
inspect logs and disk space instead of leaving this condition unresolved.

On the Pi, export a read-only, atomic snapshot without database credentials:

```bash
sudo python3 scripts/export-domain-catalogue.py --database data/data.db --output output/domain-catalogue.json
sudo python3 scripts/export-domain-catalogue.py --database data/data.db --output output/domain-catalogue.csv
```

Use the actual `DATA_DIR` if customized. The JSON export is suitable for backup and
review; the CSV opens in a spreadsheet. Schedule the JSON command daily with your
system's scheduler, writing to a backed-up directory or separate storage. The command
replaces its output atomically only after a successful read; it does not alter the DB.
Keep normal stopped-state PocketBase backups for full disaster recovery.

An authenticated HTTP alternative is `GET /api/infrareveal/domain-catalogue/export`
with a PocketBase superuser token. The HTTP JSON includes PocketBase record metadata;
the local export contains only the review fields above.

Sort pending records by flow count to prioritize review. Verify ownership and the
specific hostname/domain scope, then edit `pocketbase/observer/domain_groups.json`
and rebuild the backend. CNAME evidence and co-occurrence are investigation leads,
not automatic aliases. Shared infrastructure must not be assigned wholesale to one
app. See [domain grouping](domain-grouping.md). Approval in the catalogue records a
review decision; it does not automatically change the classifier.

## Continuous route discovery

Ordinary recordings retain lifetime route budgets. For ephemeral sessions, target,
automatic attempt, and manual attempt allowances renew hourly and survive restart.
The network's rolling-hour allowance, pacing, negative suppression, and visibility
backoff still apply. Defaults are 20 targets / 40 attempts per renewal, with at most
40 attempts per rolling hour per network/address family.

Route storage budgets count retained snapshots and evidence rather than cumulative
lifetime writes. Expiry releases capacity. Still-needed anchors count against the
limit, and a full retained budget can defer discovery until capacity is available.
Useful unexpired evidence/cache entries avoid redundant probes; a busy already-mapped
destination does not occupy a candidate slot ahead of new destinations indefinitely.

## Health and soak test

`GET /api/infrareveal/demo` reports server time, designated session, retention,
capture heartbeat, and the last successful cleanup/error. Capture is healthy when
its heartbeat is current and running; no recent visitor traffic is required.
Docker already restarts exited services and rotates logs. A Docker healthcheck alone
does not restart a hung-but-running process; use the screen/monitor output to detect it.

Run this on the Pi for about 72 hours (or add `--samples 10` for a short check):

```bash
sudo python3 scripts/monitor-demo.py --database data/data.db --output output/demo-soak.jsonl
```

The tool samples once per minute and appends health, per-session row counts, database
size, WAL size, and allocated/free database pages. Optional repeated `--pid PID`
arguments collect RSS in KiB for local processes; reselect PIDs after process restart.
Use the browser's task manager on the display PC to check its own memory.

Acceptance checks:

- Generate ordinary browsing/streaming traffic from participant Wi-Fi. Admin-only
  browsing must not appear. Pause traffic and leave a long-lived connection open.
- After 30 minutes plus one cleanup cycle, old short flows disappear. A connection
  still alive remains, but displayed volume uses only retained activity chunks.
- Restart the Pi, interrupt admin Wi-Fi, and reboot the display PC. The screen
  reconnects and resumes following the same demo session automatically.
- After several hours, new destinations can still receive route discovery; hourly
  caps and backoff may legitimately delay them.
- Catalogue counts survive cleanup/restart; repeated idle sweeps do not increment
  them. Review fields survive fresh observations. Export JSON and CSV successfully.
- Under comparable traffic load, raw row counts, browser memory, and backend memory
  settle instead of growing with uptime. Check WAL growth and cleanup errors too.
  The catalogue can grow with distinct domains and SQLite may keep freed pages.

Run `python3 scripts/test-demo-tools.py` to check the export and launcher helpers.
Local automated tests simulate retention, concurrent/repeated catalogue updates,
transaction rollback, bootstrap recovery, and 72 hours of route renewals. They do not
replace this physical radio/network/storage/browser soak test on the lab hardware.
