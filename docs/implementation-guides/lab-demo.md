# Unattended lab demo

The gateway Pi serves the map; a display PC joins `Infrareveal-admin` and opens **http://10.77.0.1/demo**. Visitors join the participant SSID, `Infrareveal` by default. Admin traffic is excluded from capture. Ethernet provides visitor Internet access. The bundled Equal Earth background works offline; the optional Mercator basemap downloads tiles/fonts.

## Enable

Follow the [Pi deployment guide](pi-deployment.md). This architecture requires a fresh application database: preserve an old installation separately and do not open its recording database with the new build. Keep the existing networking and GeoIP configuration. Enable:

```dotenv
DEMO_MODE=true
DEMO_RETENTION_MINUTES=30
DIAGNOSTICS_ENABLED=false
```

Demo mode creates a dedicated `Lab demo` session and resumes that active session after restart. It closes another active recording and refuses a competing session while demo mode is enabled. The core installation has seven application collections; full optional diagnostics adds three. There is no permanent domain catalogue or catalogue export endpoint.

The demo is a continuous session with 1–1440 minutes of rolling retention. Startup applies `DEMO_RETENTION_MINUTES`; the session's `retention_minutes` can also be adjusted while running. An ordinary continuous session defaults to five minutes. A session pins its classification and activity grouping policy.

Cleanup runs every 15 seconds, clipping traffic to the retained window, rebuilding affected activity blocks and removing unreferenced destination/route evidence. Crossing blocks retain their identity and original-start anchor while their displayed totals reflect retained samples. Keeping a socket open does not preserve expired traffic. Shrinking retention deletes data; expanding it cannot recover prior observations. SQLite reuses free pages, so file size may stay at its high-water mark.

To stop the dedicated demo, set `DEMO_MODE=false` and recreate the services using the deployment guide. Use the session controls to close or replace its continuing capture as needed.

## Display PC

1. Save the admin Wi-Fi connection for automatic reconnect and disable sleep/blanking while plugged in.
2. Install Python 3 and Chromium, copy `scripts/demo-kiosk.py`, and run it at desktop login:
   `python3 /path/to/demo-kiosk.py --url http://10.77.0.1`.
3. If needed, pass `--browser /path/to/browser`. The launcher uses a dedicated profile, waits for both API and dashboard HTML, reopens the browser after exit and reloads after a sustained gateway outage.
4. Test a display reboot while the Pi is off, then start the Pi and verify recovery without clicking Retry.

The demo follows the live edge and reconnects automatically. Capture, gateway and cleanup problems remain visible; an idle complete capture may legitimately show no traffic. Normal map pages retain pause/seek controls and activity-block browsing. An activity block is inferred service traffic, not measured browsing attention. The screen generates no synthetic visitor activity.

## Classification and routing

Service classification uses the session's registered-domain policy and explicit aliases from `pocketbase/observer/domain_groups.json`. DNS names and CNAMEs are evidence, not automatic aliases. Shared infrastructure must not be assigned wholesale to an application. Investigations can use retained typed attribution evidence or explicitly enabled diagnostics; there is no separate permanent aggregate/checkpoint lifecycle. See [domain grouping](domain-grouping.md).

Route limits renew hourly for continuous sessions: 20 automatic targets, 40 automatic attempts and ten manual attempts per scope by default. The shared network/family rolling-hour limit, pacing, cooldown and no-gain pause still apply. Reservations survive restart and recent charges survive session deletion. A path can be reused within the same session and network epoch while valid; there is no cross-session cache.

Retained route storage is capped at 100 useful publications and 16 MiB. Each successful run can publish one terminal path and one meaningful enrichment. Retention frees unreferenced evidence while retaining anchors needed by current traffic; a full retained budget defers new work. See [live route discovery](live-route-discovery.md).

## Health and soak test

`GET /api/infrareveal/demo` reports the session, retention, capture health and cleanup status. A current capture heartbeat does not require recent visitor packets. Docker restarts exited services and rotates logs; a healthcheck alone does not restart a hung process.

Run a short monitor check with `--samples 10`, or use the default 72-hour sample count:

```bash
sudo python3 scripts/monitor-demo.py --database data/data.db --output output/demo-soak.jsonl
```

The monitor records health; traffic/chunk, coverage, block and route counts; optional diagnostic counts when those collections exist; global destination/admission counts; database/WAL size; and allocated/free pages. Optional repeated `--pid PID` arguments add RSS in KiB. Reselect process IDs after restart and use the browser task manager for display memory.

Check representative browsing/streaming from participant Wi-Fi and confirm admin traffic is absent. After the retention interval plus one cleanup cycle, expired traffic must disappear even for open sockets. Verify pause/seek and activity details, restart recovery, route quota persistence, visible capture interruptions and stable resource use under comparable load. Network-wide admission rows deliberately outlive the display window, up to the operational retention horizon; this is distinct from a leak. Physical database size may retain reusable free pages.

Run `python3 scripts/test-demo-tools.py` for the offline monitor, route-audit and kiosk checks. These do not replace the radio/network/storage/browser soak test on the lab hardware.
