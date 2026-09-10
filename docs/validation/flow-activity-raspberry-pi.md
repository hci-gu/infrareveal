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

The Linux socket regression must also run in an isolated network namespace with `CAP_NET_RAW`. It sends synthetic large TCP, UDP and IPv6 frames through the actual BPF filter, socket receive and parser, checking original wire and payload counts. From the repository root on an arm64 development host with Docker:

```bash
cd pocketbase
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/infrareveal-observer-linux.test ./observer
docker run --rm --network none --cap-add NET_RAW \
  -e INFRAREVEAL_PACKET_CAPTURE_TEST=1 \
  --mount type=bind,src=/tmp/infrareveal-observer-linux.test,dst=/observer.test,readonly \
  --entrypoint /observer.test node:22-slim \
  -test.run 'TestPacket(Capture|Original)' -test.v -test.timeout 20s
```

The socket test establishes the kernel/socket boundary locally; fresh capture on the Pi is still required to validate its AP interface. Historical missing timing cannot be reconstructed from cumulative flow counters.

`TestUnmatchedActivityDoesNotBecomeCaptureLoss` checks matching expiry through the aggregator, persistence acknowledgements and migrated status/window records. It also injects queue loss to verify that real capture loss remains visible. Keep `unmatched_events` separate from `dropped_events`; existing recording flags are not rewritten.

For migration/API smoke testing, use an isolated copy of the data directory. Verify list requests for `flow_activity_status`, `flow_activity_windows` and paginated/time-filtered `flow_activity_chunks`, stable capture-window identity across heartbeats, and graceful shutdown without observer database errors.

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

Record database size before and after the hour. Count `flow_activity_chunks` at the beginning and end through the PocketBase admin/API, then calculate writes/minute and bytes/hour. In browser developer tools, record initial load and render time for a 60-minute session at wide and narrow zoom ranges. Fine activity loading must stay within bounded visible/selected intervals even when the overview spans the session. Compact cumulative summaries are separate from fine-grained history.

| Pi model / OS / build | Scenario | Proxy CPU | Proxy memory | Dropped events | Chunk writes/min | DB growth/hour | Dashboard load/render |
|---|---|---:|---:|---:|---:|---:|---:|
| _record on target_ | Idle phone | | | | | | |
| _record on target_ | HTTP/2 resources | | | | | | |
| _record on target_ | QUIC video | | | | | | |
| _record on target_ | Two clients | | | | | | |

Attach the completed table to the release or test report. A result is not acceptable if forwarding is affected, drops are hidden, history loading becomes unbounded, or content-bearing packet data is persisted. If drops occur, retain the result and visible warning as evidence, then tune queue sizes or load before release.
