# Flow Activity Raspberry Pi Validation

Use this procedure after deploying a candidate build to the minimum supported Raspberry Pi. Do not use production browsing data: the test matrix should use a dedicated phone and controlled pages or fixtures.

## Automated gates

Run before deployment:

```bash
cd pocketbase
go test -count=1 ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...

cd ../dashboard
pnpm test
pnpm build
pnpm lint
```

The deterministic backend benchmark replays 10,000 metadata-only packet events:

```bash
cd pocketbase
go test -run '^$' -bench BenchmarkActivityAggregatorReplay -benchmem -count=5 ./observer
```

Development reference only—not a Raspberry Pi result: on an Apple M1 Max running arm64 Darwin on 2026-08-25, the replay took 1.67–1.71 ms per 10,000 events and allocated about 1.07 MB. Record target-Pi results below rather than treating this figure as an acceptance measurement.

Also on 2026-08-25, a fresh local PocketBase data directory was migrated and served through the compiled application. HTTP list requests against `flow_activity_status`, `flow_activity_windows`, and a paginated/time-filtered `flow_activity_chunks` query succeeded. Repeated two-second status heartbeats updated one stable record per five-second capture window, and graceful shutdown produced no activity-observer database errors. This is a migration/API smoke check, not a substitute for raw capture or performance testing on the Pi.

## Controlled session matrix

Clear observations before each run, start a new active session, and test:

1. Idle phone for ten minutes.
2. One small image from a controlled HTTP/1.1 server.
3. Several parallel resources from a controlled HTTP/2 server.
4. Video over QUIC/HTTP/3.
5. A long-lived push or background connection.
6. Simultaneous browsing from two client devices.

For controlled web fixtures, compare activity timing to browser developer tools. This comparison validates timing only; the passive dashboard must continue calling the marks activity/transfers, never confirmed resources or response times.

Verify in every run:

- Only traffic from connected clients appears; idle infrastructure noise does not create flows or activity.
- A short transfer appears inside the longer pale connection lifetime.
- Amber outbound and cyan inbound activity are distinguishable.
- ACK-only packets can produce one-pixel packet marks without payload height.
- Disconnecting or misconfiguring `PACKET_ACTIVITY_IFACE` leaves forwarding and conntrack timelines working and produces a visible warning/hatching.
- `flow_activity_chunks.samples` contains only numeric counts and offsets. No packet payload, hostname path, URL, or browser resource label is present.
- A dashboard zoom/range request is paginated and never loads an unlimited session history.

## Measurements

Use the same five-minute warm-up and 60-minute measurement window for the idle, HTTP/2, QUIC, and two-client cases.

```bash
docker stats --no-stream proxy dashboard
docker compose logs proxy | grep 'packet activity dropped'
du -h data/data.db
```

Record database size before and after the hour. Count `flow_activity_chunks` at the beginning and end through the PocketBase admin/API, then calculate writes/minute and bytes/hour. In browser developer tools, record dashboard initial load and render time for a 60-minute session at “All,” 5m, and 1m zoom. “All” should still fetch at most the implementation's 15-minute detailed window.

| Pi model / OS / build | Scenario | Proxy CPU | Proxy memory | Dropped events | Chunk writes/min | DB growth/hour | Dashboard load/render |
|---|---|---:|---:|---:|---:|---:|---:|
| _record on target_ | Idle phone | | | | | | |
| _record on target_ | HTTP/2 resources | | | | | | |
| _record on target_ | QUIC video | | | | | | |
| _record on target_ | Two clients | | | | | | |

Attach the completed table to the release or test report. A result is not acceptable if forwarding is affected, drops are hidden, history loading becomes unbounded, or content-bearing packet data is persisted. If drops occur, retain the result and visible warning as evidence, then tune queue sizes or load before release.
