# Map and activity capture on Raspberry Pi

Use a fresh application data directory and the seven-collection model. The
[deployment guide](../implementation-guides/pi-deployment.md) describes the target
interfaces and container setup. These procedures validate the new capture path;
local namespace tests do not establish physical AP performance.

## Automated checks

From `pocketbase`, run:

```bash
go test ./...
go test -race ./...
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go build ./...
GOOS=linux GOARCH=arm GOARM=7 CGO_ENABLED=0 go build ./...
go test -run '^$' -bench 'Benchmark(ProjectThirtyMinutes|RebuildBlocksThirtyMinutes|MapWindow)' -benchmem ./observer ./timeline
```

Run `pnpm test`, `pnpm lint` and `pnpm build` from the repository root. The block
benchmarks distinguish the pure full projection from steady-state database work;
the map-window benchmark exercises the product API reader with dense captured
bins. Preserve scenario sizes alongside results.

The Linux socket tests send synthetic large TCP, UDP and IPv6 frames through the
real filter, receive loop and parser. They also check idle capture heartbeats and
shutdown. On an arm64 development host with Docker:

```bash
cd pocketbase
GOOS=linux GOARCH=arm64 CGO_ENABLED=0 go test -c -o /tmp/infrareveal-observer-linux.test ./observer
docker run --rm --network none --cap-add NET_RAW \
  -e INFRAREVEAL_PACKET_CAPTURE_TEST=1 \
  --mount type=bind,src=/tmp/infrareveal-observer-linux.test,dst=/observer.test,readonly \
  --entrypoint /observer.test node:22-slim \
  -test.run 'TestPacket(Capture|Original)' -test.v -test.timeout 20s
```

Use the isolated network fixtures for gateway isolation, NFQUEUE fail-open and
Scamper method/NAT coverage. These operate in container network namespaces and do
not require public probe targets. See the corresponding scripts under `scripts/`.

## Fresh-data and lifecycle checks

A fresh core database contains `sessions`, `traffic_chunks`, `capture_intervals`,
`activity_blocks`, `destinations`, `route_evidence` and `probe_runs`. Full optional
diagnostics adds `flow_diagnostics`, `dns_queries` and `gate_events`. Auth/system
collections are outside this count. Enabling only the Lab gate adds its required
audit collection.

Use `/api/infrareveal/sessions/{id}/manifest`, `/map`, `/blocks` and `/revisions` for
public reads. Map requests require Unix-millisecond `from` and `to` and at most
thirty minutes; follow `next_cursor` until complete. Block lists use their own
bounded pages. Verify the assembled map counters equal captured stored counters
for the same complete source bins. Direct collection APIs remain private.

Check start, end, clear and restart. Restart within a source chunk must preserve
its earlier capture epoch, seal previous labels and continue in a new epoch.
Capture gaps remain visible. Clear removes observations after draining workers;
probe charges survive. Rolling retention keeps crossing-block identity and
recomputes its retained counts. Saved recordings retain their history.

## Controlled traffic matrix

Start a fresh session for each case:

1. An idle client for ten minutes, with advancing complete capture coverage.
2. Repeated short HTTP downloads, including transfers missed by conntrack.
3. Parallel resources and two simultaneous services sharing an IP.
4. QUIC traffic, encrypted DNS and unresolved independent endpoints.
5. A long-lived connection with payload bursts separated by the quiet gap.
6. Two clients, address/lease reuse, and a capture interface interruption.

Compare controlled transfer payload lengths with captured wire and payload-byte
counts. Wire bytes include transport/network overhead. Do not sum conntrack
counters into capture. DNS evidence should classify supported traffic; ambiguity
and missing evidence must remain visible. Verify that one connection can contribute
to several activity blocks, simultaneous services can overlap, and ACK-only
traffic does not extend activity spans.

`traffic_chunks.samples` contains only numeric offsets and directional wire,
payload-byte and packet counts. Packet contents, URL paths and browser resource
names are not stored. Gateway-generated probes and local infrastructure traffic
are excluded from participant capture.

Disable or misconfigure `PACKET_ACTIVITY_IFACE` during a test. Forwarding must
continue while the manifest and coverage show unavailable capture. Injected queue
loss must produce partial coverage and a cumulative dropped count. Unknown
capture must never look like a measured quiet interval.

## Resource measurements

After a five-minute warm-up, measure idle, parallel HTTP, QUIC and two-client
traffic over a representative interval. Record the actual duration, Pi model,
OS, build, configuration and load; do not extrapolate a brief smoke into a soak.

Use `docker stats --no-stream` for process resources. Record database and WAL size,
chunk/coverage/block row counts, capture generations and revision changes before
and after. Report logical persistence flushes separately from SQLite writes and
physical I/O. Measure map endpoint latency for both source-resolution and coarse
windows, including pagination and initial browser rendering.

| Scenario | Duration | CPU / RSS | Capture drops | Flushes / second | DB + WAL growth | Map p50 / p95 |
| --- | --- | --- | --- | --- | --- | --- |
| Idle | | | | | | |
| Parallel HTTP | | | | | | |
| QUIC | | | | | | |
| Two clients | | | | | | |

A bounded rolling session should stop accumulating expired product rows. Block
rebuilding should read only its correction tail plus newly expired retention
contributions, and the browser should load bounded windows. Investigate hidden
loss, increasing steady-state memory or work that grows with the entire recording.
Store logs and measurements under `output/`; record observed limitations in the
validation report before marking the gateway checklist complete.
