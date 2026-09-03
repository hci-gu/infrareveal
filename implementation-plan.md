# Proxy Lab experiment — detailed implementation plan

Status: **Code implementation complete; physical Raspberry Pi acceptance validation pending**

Companion UI concept: [implementation-plan.html](implementation-plan.html)

Target: `debug-dashboard` plus opt-in, lab-only gateway support

Production dashboard impact: no new UI; shared session behaviour must remain compatible

## How to use this plan

- Check an item only when its implementation and the tests listed beneath it are complete.
- Finish each numbered milestone in order. Later milestones assume the contracts introduced by earlier milestones.
- Keep passive visualization changes separate from traffic-changing lab-mode changes in commits and review.
- If implementation reveals that a decision below must change, update this document before changing the contract in code.
- Commands are shown from the repository root unless prefixed with `cd pocketbase`.

## Progress summary

- [x] Agree on the experiment boundary and interaction concept.
- [x] Produce the reviewable UI concept in `implementation-plan.html`.
- [x] M0 — Establish a clean dependency and test baseline.
- [x] M1 — Add a multi-experiment shell to `debug-dashboard`.
- [x] M2 — Define the shared trace and gate event contracts.
- [x] M3 — Build deterministic recorded-session projection.
- [x] M4 — Implement the Remotion proxy pipeline UI.
- [x] M5 — Add the passive live trace hub and stream.
- [x] M6 — Connect the live trace stream to the debug UI.
- [x] M7 — Build the platform-independent gate controller core.
- [x] M8 — Add the Linux NFQUEUE adapter and guarded network rules.
- [x] M9 — Add authenticated control APIs and durable gate auditing.
- [x] M10 — Connect the turn-based UI to real gate state.
- [x] M11 — Add strict single-flow and DNS diagnostic modes.
- [ ] M12 — Complete load, failure, privacy, and Raspberry Pi validation. _(All local/automated/Linux-container checks pass; physical Pi soak and client matrix remain.)_
- [x] M13 — Update operational documentation and finish the implementation handoff.

---

## 1. Outcome and boundaries

### 1.1 Goals

- [x] A recorded session can be opened in the debug dashboard and replayed as a node-and-token explanation of the gateway pipeline.
- [x] An active session can use the same scene, follow a delayed live edge, scrub backward, and return to live without reloading.
- [x] Replay supports extreme slow motion and single-frame stepping through Remotion.
- [x] The scene distinguishes actual packet forwarding from passive observation and later derivation.
- [x] A lab-only mode can hold the first packet(s) of selected new flows until an operator accepts or rejects the flow.
- [x] The real wait is visible in the controlled client and becomes a timestamped event in the session timeline.
- [x] A strict diagnostic mode can step individual packets for exactly one selected client and flow.
- [x] DNS can be gated separately from forwarded-flow gating.
- [x] Every queue overflow, watchdog release, capture gap, and trace drop is visible instead of being rendered as normal traffic.
- [x] Normal gateway mode remains behaviourally equivalent to the current NAT gateway.

### 1.2 Non-goals

- [x] Do not restore transparent TLS interception as a normal gateway feature.
- [x] Do not claim that encrypted bursts are HTTP requests, resources, response times, or page loads.
- [x] Do not persist packet payloads or arbitrary packet prefixes.
- [x] Do not make the production dashboard depend on lab-mode code.
- [x] Do not manually approve every packet from a room of clients.
- [x] Do not attempt to override arbitrary browser, phone, application, or remote-server timeouts from the gateway.
- [x] Do not make destination enrichment or traceroute part of the packet forwarding path.

### 1.3 Accepted design decisions

- [x] Use **flow admission** as the default manual unit: TCP SYN or first UDP datagram.
- [x] Mark explanatory historical transitions as `derived` timing when the gateway did not record the real processing timestamp.
- [x] Follow live approximately 500 ms behind the newest event to absorb delivery jitter.
- [x] Fail open when the queue controller is missing, overloaded, or shutting down.
- [x] Gate selected forwarded TCP/UDP traffic first; add local DNS gating later.
- [x] Permit strict per-packet mode only with exactly one client and one complete five-tuple filter.
- [x] Keep high-volume live trace events ephemeral; reconstruct recorded bursts from existing `flow_activity_chunks`.
- [x] Persist only low-volume gate audit events as a new PocketBase collection.

---

## 2. Current codebase map

The implementation must build on these existing paths instead of creating a second session runtime.

| Current capability | Existing code | Implementation consequence |
| --- | --- | --- |
| NAT forwarding | `entrypoint.sh` installs `FORWARD` and `MASQUERADE` rules | Lab rules must be inserted before the broad outbound accept rule and removed idempotently. |
| DNS observation | `pocketbase/observer/dnsmasq.go` tails dnsmasq logs | DNS is local gateway traffic, not forwarded traffic; it needs a separate later gate. |
| Flow identity/lifetime | `pocketbase/observer/conntrack.go` samples every two seconds | Recorded flow tokens begin when the sampler first sees a flow, not necessarily at the first packet. |
| Fine activity | `pocketbase/observer/packet_activity_linux.go` and `packet_activity.go` capture headers and store 50 ms buckets in five-second chunks | Reuse this data for recorded burst tokens and tap the existing in-memory pipeline for lower-latency live visualization. |
| Attribution | `pocketbase/observer/correlator.go` runs every three seconds | Attribution must be rendered as a derived branch, not a forwarding stage. |
| Destination and routes | `pocketbase/observer/destination.go` enriches every three seconds and traces every 30 seconds | These transitions happen well after traffic and must remain asynchronous in the scene. |
| Session windows | `pocketbase/session_timeline.go` supplies manifests and windowed LOD data | Extend this endpoint only for durable `gate_events`; do not send ephemeral trace traffic through it. |
| Shared frontend runtime | `packages/session-state/src/timeline/` owns time, live edge, window loading, caching, and reconciliation | Reuse its cursor and selected session; do not create a competing playback clock. |
| Existing debug UI | `debug-dashboard/src/App.tsx` is one large session-playback experiment | Move it behind an experiment route without changing its behaviour. |
| Existing Remotion integration | `debug-dashboard/src/remotion/SessionComposition.tsx` and Player control code in `App.tsx` | Reuse its Player event patterns, but implement a separate pure proxy-lab scene. |
| Container privileges | `docker-compose.yml` uses host networking and `privileged: true` | NFQUEUE is feasible on the target, but support must still be detected and surfaced at runtime. |
| Static route fallback | `dashboard/nginx.conf` and the debug image serve SPA assets | Add an equivalent explicit debug-dashboard nginx fallback test when routes are introduced. |

### 2.1 Architectural invariant

```text
data plane
client -> wlan0 -> conntrack/netfilter -> [optional lab gate] -> FORWARD -> NAT -> uplink

observation plane
wlan0 -> header observer -> 50 ms buckets -> chunks -> PocketBase
dnsmasq log -------------------------------> PocketBase
conntrack table -> sampler -> correlator/enricher/routes -> PocketBase
PocketBase + ephemeral trace stream -> shared clock -> debug Remotion scene
```

- [x] Preserve the rule that failure in observation, trace streaming, PocketBase persistence, or the debug dashboard cannot block forwarding when lab mode is off.
- [x] Make solid lines in the UI represent the data plane and dashed lines represent observation/derivation.
- [x] Treat packet movement between drawn nodes as explanatory interpolation, not measured hop latency.

---

## 3. Target module boundaries

### 3.1 Frontend layout

```text
debug-dashboard/src/
  App.tsx                              # router only
  pages/
    ExperimentsPage.tsx                # experiment/session launcher
  experiments/
    session-playback/
      SessionPlaybackPage.tsx          # current App implementation
    proxy-lab/
      ProxyLabPage.tsx                 # orchestration and Player controls
      constants.ts
      types.ts
      data/
        traceClient.ts                 # authenticated fetch/SSE stream
        gateClient.ts                  # control/status HTTP client
        demoTransport.ts               # deterministic non-Pi fixture source
      model/
        projectRecordedEvents.ts
        mergeLiveEvents.ts
        projectProxyScene.ts
        temporalEventIndex.ts
        graphLayout.ts
      state/
        proxyLabStore.ts               # experiment-only Zustand store
        selectors.ts
      components/
        ModeSwitcher.tsx
        PipelinePlayer.tsx
        QueueInspector.tsx
        PipelineFilters.tsx
        GateHealth.tsx
        GateArmDialog.tsx
      remotion/
        ProxyLabComposition.tsx
        PipelineGraph.tsx
        TrafficToken.tsx
        PipelineLegend.tsx
        PipelineHUD.tsx
      *.test.ts / *.test.tsx
  shared/
    activity/decodeActivityChunk.ts    # extracted from current session model
```

### 3.2 Backend layout

```text
pocketbase/
  debugtrace/
    event.go                           # trace vocabulary; no observer imports
    hub.go                             # bounded ring and subscriptions
    burst.go                           # 50 ms flow/direction coalescing
    routes.go                          # session-scoped SSE endpoint
    *_test.go
  labgate/
    config.go
    controller.go                      # platform-neutral policy/state machine
    flow.go                            # tuple grouping and decision cache
    audit.go                           # async durable event writer
    routes.go                          # authenticated status/control API
    packet_queue.go                    # adapter interface
    nfqueue_linux.go                   # real Linux implementation
    nfqueue_other.go                   # unsupported-platform stub
    *_test.go
  netmeta/
    flow.go                            # canonical tuple, direction, key
    packet.go                          # bounded IPv4/IPv6 TCP/UDP header parsing
    *_test.go
  migrations/
    <timestamp>_gate_events.go
```

### 3.3 Ownership rules

- [x] `packages/session-state` owns durable session entities and the one playback clock used by both dashboards.
- [x] `debug-dashboard/experiments/proxy-lab` owns display mode, filters, selected graph item, trace ring state, gate form state, and operator controls.
- [x] `debugtrace` owns ephemeral visualization events and may never import PocketBase observer packages.
- [x] `labgate` owns kernel queue verdicts and may emit `debugtrace.Event` through a narrow sink interface.
- [x] `netmeta` owns canonical flow identity so observer, trace, and gate code cannot disagree on tuple direction or key formatting.
- [x] The production `dashboard` imports none of `debug-dashboard` or `labgate`.
- [x] No backend package imports frontend concepts such as graph node positions or Remotion frames.

---

## 4. Cross-language contracts

### 4.1 Canonical flow identity

Add a platform-neutral `netmeta.FlowTuple` and migrate the existing observer key generation to it before adding the gate.

```go
type Direction string

const (
    ClientToRemote Direction = "client_to_remote"
    RemoteToClient Direction = "remote_to_client"
)

type FlowTuple struct {
    Protocol   string
    ClientIP   netip.Addr
    ClientPort uint16
    RemoteIP   netip.Addr
    RemotePort uint16
}

func (t FlowTuple) Key() string
```

- [x] Preserve the current key format exactly so existing `flows` and `flow_activity_chunks` continue to correlate.
- [x] Move or wrap the current `observer.flowKey` implementation without rewriting existing records.
- [x] Normalize protocol casing and IP representation before computing the key.
- [x] Reject zero/invalid remote ports for TCP/UDP.
- [x] Keep direction separate from identity so both directions resolve to the same key.
- [x] Add golden tests using current IPv4, IPv6, TCP, UDP, inbound, and outbound parser fixtures.
- [x] Prove old and new key functions return identical strings for every existing test case before deleting the old helper. _(The observer's unchanged flow-key assertions now execute through `netmeta`, and conntrack uses the same constructor.)_

### 4.2 Pipeline trace event

Use equivalent Go and TypeScript representations. JSON names are the wire contract.

```ts
type PipelineEvent = {
  id: string
  sequence: number
  sessionId: string
  traceId: string
  parentId?: string
  kind: 'dns' | 'flow' | 'burst' | 'attribution' | 'destination' | 'route' | 'gate' | 'health'
  stage: PipelineStage
  direction?: 'client_to_remote' | 'remote_to_client'
  occurredAtMs: number
  processedAtMs?: number
  timing: 'observed' | 'derived'
  summary: PipelineEventSummary
}
```

`PipelineEventSummary` must be a typed allowlist, not `Record<string, unknown>`:

- `protocol`
- `clientIp`
- `clientPort`
- `remoteIp`
- `remotePort`
- `flowKey`
- `dnsName`
- `dnsType`
- `hostname`
- `confidence`
- `wireBytes`
- `payloadBytes`
- `packetCount`
- `tcpFlags`
- `verdict`
- `verdictSource`
- `droppedEvents`
- `captureComplete`

- [x] Do not add raw packet bytes, HTTP headers, cookies, URLs, request bodies, response bodies, TLS payload, or arbitrary maps.
- [x] Allocate `sequence` in the hub, not in individual observer goroutines. _(Producer `Event` values default to sequence zero; `BurstInput` has no sequence field.)_
- [x] Define deterministic ordering as `(occurredAtMs, sequence, id)`.
- [x] Use source/network time for `occurredAtMs` and gateway processing time for `processedAtMs`.
- [x] Set `timing: derived` whenever an old record is being turned into an explanatory transition with no measured stage timestamp.
- [x] Version the stream envelope independently from the event schema so clients can reject incompatible streams cleanly.

### 4.3 Durable gate audit event

Add `GateEvent` to `packages/session-state/src/data/types.ts` and the matching PocketBase collection.

```ts
type GateEvent = {
  id: string
  session: string
  decision_id: string
  flow_key: string
  client_ip: string
  destination_ip: string
  source_port: number
  destination_port: number
  protocol: string
  packet_count: number
  state: 'queued' | 'approved' | 'rejected' | 'expired' | 'bypassed' | 'drained'
  actor: string
  reason: string
  verdict_source: 'operator' | 'watchdog' | 'overflow' | 'shutdown' | 'system'
  queued_at: string
  decided_at?: string
  wait_ms: number
  created: string
}
```

- [x] Store one durable record per decision lifecycle, updating it exactly once from `queued` to its terminal state from backend code.
- [x] Deny client-side create, update, and delete rules for the collection.
- [x] Allow list/view only under the same visibility policy as session flow data.
- [x] Add indexes for `(session, queued_at)`, `(session, decision_id)`, and `(session, flow_key)`.
- [x] Add `gateEvents` to session manifest counts and detail windows.
- [x] Add a `gateEvents` temporal index and entity map to the shared state with the same paging/eviction semantics as DNS detail.
- [x] Subscribe to realtime `gate_events` so a decision appears on the timeline without a full reconciliation.

---

## 5. M0 — Dependency and baseline preparation

The previous project direction requires updating existing packages before installing anything new. Keep these changes isolated from feature work.

### 5.1 Capture the baseline

- [x] Record `git status --short` and preserve unrelated user changes.
- [x] Run and record the current results of:

  ```bash
  pnpm test
  pnpm build
  pnpm lint
  cd pocketbase && go test ./...
  ```

- [x] Fix or explicitly document pre-existing failures before changing dependencies. _(No failures; both Vite builds emitted only the existing >500 kB chunk warning.)_
- [x] Build the current proxy image once for the target architecture. _(The check found and fixed the old arm/v6 runtime mismatch; `infrareveal-proxy:m0` now builds for linux/arm64.)_

### 5.2 Update existing dependencies first

- [x] Run `pnpm outdated -r` and review every direct workspace dependency.
- [x] Upgrade existing frontend dependencies to mutually compatible latest stable versions. _(TypeScript remains at 6.0.3 because the current `typescript-eslint` peer range is `<6.1.0`; all other direct packages resolve at latest.)_
- [x] Update the root `packageManager` pin and Docker Corepack preparation together if pnpm changes.
- [x] Run all frontend tests/build/lint after the upgrade.
- [x] Run `cd pocketbase && go list -m -u all`.
- [x] Upgrade PocketBase and existing direct Go dependencies in a dedicated change.
- [x] Follow PocketBase migration/API release notes for every version crossed; update custom route and migration APIs as required.
- [x] Update the Go toolchain and builder image together if the upgraded dependencies require it.
- [x] Run `go mod tidy`, `go test ./...`, and the container build after the Go upgrade.
- [x] Confirm existing session manifests, window endpoints, PocketBase realtime, and migrations still work against copied test data. _(Disposable copied `pb_data` migrated and served successfully; collection, manifest, and detail-window requests passed. Existing realtime contract tests remain green.)_

### 5.3 Install only the required new dependencies

- [x] Add the latest compatible `react-router-dom` to `@infrareveal/debug-dashboard` after the update pass.
- [x] Evaluate the latest stable `github.com/florianl/go-nfqueue/v2` release against these requirements:
  - Linux/arm64 support.
  - No CGO requirement, preserving `CGO_ENABLED=0`.
  - Asynchronous verdict support by packet ID.
  - Copy-range, max-queue-length, and fail-open configuration.
  - Context-aware shutdown or a reliable close/unblock path.
- [x] Add the NFQUEUE library only after the evaluation passes.
- [x] Do not add a graph library; render the fixed teaching topology with SVG/React.
- [x] Do not add another state library; Zustand already exists in the debug dashboard and shared runtime.
- [x] Re-run the complete baseline after installation.

**M0 exit criteria**

- [x] All existing behaviour passes on updated dependencies.
- [x] The proxy still cross-compiles with `CGO_ENABLED=0` for Linux/arm64.
- [x] Dependency-only changes can be reviewed independently from the experiment.

---

## 6. M1 — Multi-experiment debug-dashboard shell

### 6.1 Introduce routing without changing current behaviour

- [x] Move the current contents of `debug-dashboard/src/App.tsx` into `experiments/session-playback/SessionPlaybackPage.tsx`.
- [x] Keep existing helper components beside that page initially; do not combine this move with unrelated cleanup.
- [x] Replace `App.tsx` with a small `BrowserRouter` route table.
- [x] Add routes:
  - `/` — experiment/session index.
  - `/timeline/:sessionID` — existing session playback experiment.
  - `/proxy-lab/:sessionID` — new experiment.
  - `*` — redirect to `/`.
- [x] Preserve existing query-string time/deep-link behaviour when entering `/timeline/:sessionID`.
- [x] If the existing timeline is opened without a session ID during migration, resolve the active session and replace the URL.
- [x] Add `debug-dashboard/nginx.conf` with `try_files $uri $uri/ /index.html`.
- [x] Copy that nginx configuration from the runtime stage in `debug-dashboard/Dockerfile`.
- [x] Confirm direct route entry works in the built debug image.
- [x] Add an optional `debug-dashboard` Compose profile/service on a non-production port so the experiment can run on the Pi without replacing the production dashboard.

### 6.2 Build the experiment index

- [x] Load sessions with the shared `getSessions()` API.
- [x] Group active and recorded sessions visually.
- [x] Render an experiment card for each session:
  - `Session timeline` links to `/timeline/:sessionID`.
  - `Proxy pipeline` links to `/proxy-lab/:sessionID`.
- [x] Show connection/loading/error/empty states.
- [x] Subscribe or poll for session-list changes so newly activated sessions appear.
- [x] Keep the page usable without lab mode; the passive proxy visualization is always available.

### 6.3 Add a deterministic demo route

- [x] Support `VITE_PROXY_LAB_DEMO=true` or a `?demo=1` development-only switch.
- [x] Feed a fixed fixture containing DNS, TCP, UDP/QUIC, attribution, route, queue, verdict, drop, and capture-gap examples.
- [x] Seed all demo IDs and timestamps so screenshots and tests are repeatable.
- [x] Ensure production builds do not enable demo transport implicitly.

**M1 tests**

- [x] Direct entry into all three routes works after a production build.
- [x] Existing timeline tests still pass after moving the page.
- [x] Route changes dispose the previous session controller and do not leave realtime subscriptions running. _(The routed page retains the shared hook's effect cleanup, which calls `sessionController.dispose()` on route unmount.)_
- [x] The index handles zero, one, and multiple active sessions defensively.

---

## 7. M2 — Shared trace and gate contracts

### 7.1 Extract flow identity

- [x] Create `pocketbase/netmeta` with `FlowTuple`, `Direction`, and `Key()`.
- [x] Refactor conntrack parsing to return or construct the shared tuple.
- [x] Refactor packet-activity parsing to use the shared tuple and direction.
- [x] Add a parser for an IP packet beginning at the network header for NFQUEUE input; do not assume an Ethernet header.
- [x] Bound all reads by the copied length and validate IPv4 IHL, IPv6 extension chains, TCP data offset, and UDP length.
- [x] Reject fragments that cannot be safely associated with a complete transport tuple.
- [x] Keep the existing observation scope rules outside generic parsing so the gate can apply a different explicit policy.

### 7.2 Implement trace types and sink

- [x] Add `debugtrace.Event`, enums, and typed `Summary`.
- [x] Define a minimal sink interface:

  ```go
  type Sink interface {
      TryEmit(Event) bool
      TryBurst(BurstInput) bool
  }
  ```

- [x] Provide a zero-allocation/no-op sink for disabled tracing.
- [x] Make `TryEmit` and `TryBurst` non-blocking by contract.
- [x] Add counters for rejected events when the ingress buffer is full.
- [x] Add JSON golden tests shared conceptually with frontend fixture tests. _(Both test suites load `testdata/pipeline-event-v1.json`.)_

### 7.3 Define frontend types

- [x] Mirror the wire types in `proxy-lab/types.ts`.
- [x] Add a runtime decoder that rejects unknown protocol versions and malformed event envelopes.
- [x] Treat unknown future event kinds/stages as ignorable, not fatal to the whole stream.
- [x] Validate numeric values for finiteness and non-negative packet/byte counts.
- [x] Unit-test decoding of valid, partial optional, unknown, and maliciously oversized payloads.

**M2 exit criteria**

- [x] Observer tests prove flow-key compatibility.
- [x] The same fixture JSON decodes into the expected Go and TypeScript event shape.
- [x] No contract allows payload bytes or arbitrary user-controlled metadata.

---

## 8. M3 — Deterministic recorded-session projection

### 8.1 Extract reusable activity decoding

- [x] Move `decodeActivityChunk` and its pure supporting types from `debug-dashboard/src/model/sessionModel.ts` into `debug-dashboard/src/shared/activity/decodeActivityChunk.ts`.
- [x] Update the existing timeline model to import it without changing results.
- [x] Move the current decoder tests with it and retain malformed-payload coverage.
- [x] Avoid moving this into `session-state` unless the production dashboard also needs decoded bucket samples; keep UI projection concerns out of shared state.

### 8.2 Project durable records into explanatory events

Implement `projectRecordedEvents(data, gateEvents, range)` using this mapping:

| Durable source | Event(s) | Time | Timing label | Scene path |
| --- | --- | --- | --- | --- |
| `Flow.start` | `flow_discovered` | parsed `start` | observed by sampler | client → wlan0 → conntrack, then explanatory continuation to NAT/remote |
| Activity sample with outbound values | `burst_observed` | `chunk_start + offset` | observed | wlan0 → NAT → remote |
| Activity sample with inbound values | `burst_observed` | `chunk_start + offset` | observed | remote → NAT → wlan0 → client |
| `DNSQuery.timestamp` | `dns_query_observed` and answer update | timestamp / updated | observed record, derived transition | client → dnsmasq → PocketBase |
| `FlowAttribution.observed_at` | `flow_attributed` | observed_at | derived conclusion | correlator → PocketBase → debug UI |
| `Destination.last_seen` | `destination_enriched` | last_seen | derived | enricher → PocketBase |
| `Route.completed_at` | `route_completed` | completed_at | observed completion | route worker → PocketBase |
| `GateEvent.queued_at` | `gate_waiting` | queued_at | observed | conntrack → flow gate |
| terminal gate event | `gate_verdict` | decided_at | observed | gate → accept/drop branch |

- [x] Do not infer a destination hostname from an IP when no attribution exists.
- [x] Carry attribution confidence into the event summary and visual treatment.
- [x] Represent incomplete/lossy activity windows with a gap event or scene overlay.
- [x] Collapse samples that have both inbound and outbound counts into two directional tokens sharing the same source bucket.
- [x] Use stable IDs derived from collection ID, bucket offset, direction, and event kind.
- [x] Cache per-record projections by PocketBase revision so realtime updates do not rebuild the entire session.

### 8.3 Add a temporal event index

- [x] Implement sorted bucket indexing by epoch milliseconds rather than scanning the entire event array per frame.
- [x] Expose `query(fromMs, toMs, filters)` and `nearestBefore(cursorMs, traceId)`.
- [x] Index by client, trace ID, kind, stage, and direction.
- [x] Preserve deterministic ordering after incremental inserts.
- [x] Bound retained projected detail to the shared viewport plus prefetch margin. _(Projection accepts the already-windowed shared detail range and filters before indexing.)_
- [x] Evict recorded projection cache entries when their corresponding shared detail page is evicted.

### 8.4 Define token projection

- [x] Define a fixed `graphLayout.ts` with named nodes and normalized coordinates for a 1600×900 composition.
- [x] Define allowed paths explicitly; do not calculate arbitrary graph traversal in render frames.
- [x] Project each event into a `SceneToken` containing path, start/end time, colour, scale, provenance, and selection ID.
- [x] Interpolate position only from `cursorMs`, `startMs`, and `endMs`.
- [x] Clamp before/after values so seeking cannot leave NaN transforms.
- [x] Use a deterministic hash of `event.id` for small lane offsets when simultaneous tokens overlap.
- [x] Enforce a default maximum of 180 visible tokens.
- [x] Aggregate overflow by `(client, stage, direction, 50 ms bucket)` and render a count token.
- [x] Never drop selected or queued gate tokens during visual aggregation.

**M3 tests**

- [x] The same input and cursor produce deep-equal scene models across repeated runs.
- [x] Events with identical timestamps sort consistently by sequence and ID.
- [x] A 60-minute synthetic session queries a 30-second viewport without iterating every session event.
- [x] Activity capture gaps are distinguishable from zero activity.
- [x] Flow, DNS, attribution, route, and gate fixtures render on the correct plane/path.

---

## 9. M4 — Remotion pipeline experiment UI

### 9.1 Page orchestration

- [x] Implement `ProxyLabPage` using `useParams()` and `useGatewayData(sessionID)`.
- [x] Use `useFlowActivityRange()` for the visible/prefetched detail range.
- [x] Read playback state and cursor from `sessionTimelineStore` with `useStore` selectors.
- [x] Keep experiment-specific UI state in a vanilla Zustand `proxyLabStore`.
- [x] Reset only proxy-lab UI state when changing sessions; let the shared controller own data teardown.
- [x] Display a clear error when the route session does not exist instead of silently selecting another session.

### 9.2 Experiment-only Zustand state

The store should contain:

```ts
type ProxyLabState = {
  mode: 'replay' | 'live-observe' | 'turn-based' | 'strict'
  filters: {
    clientIps: string[]
    protocols: string[]
    kinds: PipelineEventKind[]
    directions: Direction[]
  }
  selectedEventId: string | null
  selectedTraceId: string | null
  traceConnection: 'idle' | 'connecting' | 'live' | 'reconnecting' | 'gap' | 'error'
  ephemeralEvents: Map<string, PipelineEvent>
  oldestSequence: number | null
  newestSequence: number | null
  traceDropped: number
  gateStatus: GateStatus | null
  pendingDecisions: Map<string, GateDecision>
  controlError: string | null
}
```

- [x] Exclude `cursorMs`, `liveEdgeMs`, playback rate, and selected session from this store.
- [x] Mutate maps in controlled store actions and bump explicit version counters for React selectors.
- [x] Cap ephemeral events by both event count and time window.
- [x] Preserve pending gate items even when their visualization event ages out of the trace ring.
- [x] Clear operator token and control errors when leaving the route.

### 9.3 Remotion composition

- [x] Create `ProxyLabComposition` as a pure component of serializable props plus `useCurrentFrame()`.
- [x] Convert frame to epoch time with shared `timeForFrame()`/`frameForTime()` helpers.
- [x] Keep the node layout constant and animate tokens with transforms/opacity only.
- [x] Do not use wall-clock time, `Math.random()`, timers, subscriptions, layout measurement, or DOM mutation inside the composition.
- [x] Put all buttons, queue actions, filters, and network requests outside the composition.
- [x] Visually distinguish:
  - cyan outbound traffic;
  - green inbound traffic;
  - violet derivation;
  - amber held traffic;
  - rose rejected/dropped traffic;
  - hatching for unknown capture windows.
- [x] Dim the gate node outside turn-based/strict modes.
- [x] Show `OBSERVED` or `DERIVED TIMING` in the inspector for selected transitions.
- [x] Label route probes as gateway approximations, not client packet paths.

### 9.4 Player controls

- [x] Reuse the proven PlayerRef event pattern from the existing debug session page.
- [x] Add playback rates `0.05`, `0.1`, `0.25`, `0.5`, `1`, `2`, and `4`.
- [x] Add previous/next event controls in addition to fixed time jumps.
- [x] Single-frame buttons move exactly one frame at the composition FPS.
- [x] Scrubbing an active session changes shared playback from `following` to `paused`.
- [x] “Go live” seeks to `liveEdgeMs - 500` and restores `following`.
- [x] In turn-based mode, keep the current approval queue visibly marked `NOW` even when the scene is displaying the past.
- [x] Show a warning that decisions affect current traffic while viewing historical time.

### 9.5 Responsive/accessibility requirements

- [x] Keep the graph at a stable composition aspect ratio; allow horizontal inspection on narrow screens rather than reflowing node coordinates.
- [x] Move the queue below the player below the desktop breakpoint.
- [x] Give every control an accessible name and visible focus state.
- [x] Provide text/status equivalents for colour and motion.
- [x] Honour `prefers-reduced-motion` by disabling autonomous preview motion while retaining scrubbed state changes.
- [x] Ensure queue decisions are keyboard reachable and do not depend on drag gestures.

**M4 tests and review**

- [x] Projector/token math has unit tests at start, midpoint, end, and out-of-range frames.
- [x] Player event tests cover play, pause, seek, speed, detach-live, and go-live transitions.
- [x] Demo route visually matches the approved HTML concept at desktop and narrow widths. _(Reviewed through real-browser captures at 1680 px and 390 px.)_
- [x] No React warning, console error, or hydration/layout exception appears during a 10-minute demo run. _(The pure scene is exercised over 18,000 frames; browser interaction reports zero warnings/errors.)_

---

## 10. M5 — Passive live trace hub

### 10.1 Hub configuration

Add environment-backed configuration with conservative bounds:

```text
DEBUG_TRACE_ENABLED=false
DEBUG_TRACE_RING_EVENTS=20000
DEBUG_TRACE_RETENTION_SECONDS=30
DEBUG_TRACE_INGRESS_BUFFER=8192
DEBUG_TRACE_SUBSCRIBER_BUFFER=256
DEBUG_TRACE_BATCH_MS=50
DEBUG_TRACE_MAX_BATCH=200
```

- [x] Parse with minimum/maximum bounds and log the effective configuration once.
- [x] Disabled tracing must use the no-op sink and allocate no ring/subscriber goroutines.
- [x] Enable passive tracing independently from `LAB_GATE_ENABLED`.

### 10.1.1 Wire the hub into application startup

- [x] Construct the trace config and hub before starting observer goroutines in `pocketbase/main.go`.
- [x] Register the trace route with the same PocketBase router used by the session timeline endpoints.
- [x] Pass the hub through the new sink parameter on `StartDNSMasqIngestor`, `StartConntrackSampler`, `StartPacketActivityObserver`, `StartFlowCorrelator`, and `StartDestinationEnricher`.
- [x] Pass a no-op sink rather than sprinkling `nil` checks throughout observers.
- [x] Close the hub from `OnTerminate` after producers stop and before process exit.
- [x] Ensure route registration and disabled configuration do not start duplicate hubs if PocketBase serve hooks run more than once in tests. _(The runtime is constructed once outside `OnServe`; route binding never constructs a hub.)_

### 10.2 Ring and subscriber design

- [x] Give one hub goroutine ownership of sequence assignment and ring mutation.
- [x] Accept observer input through a bounded channel with non-blocking `TryEmit`.
- [x] Retain events until either event-count or age retention is exceeded.
- [x] Subscribe using an `afterSequence` cursor.
- [x] Return an explicit `gap` envelope if the requested sequence predates the ring.
- [x] Batch at most 200 events or 50 ms, whichever comes first.
- [x] Never block hub ingestion on a slow browser subscriber.
- [x] Track per-subscriber drops and include them in the next successful status envelope.
- [x] Remove subscribers immediately on request cancellation.
- [x] Send a heartbeat every 15 seconds to keep proxies from considering the connection idle.

### 10.3 Coalesce packet activity before streaming

- [x] Feed packet metadata into a dedicated burst ingress path after the current capture goroutine has enqueued it, not directly from `Recvfrom`.
- [x] Group by `(session, 50 ms bucket, flow key, direction)`.
- [x] Sum wire bytes, payload bytes, packet count, and TCP flags.
- [x] Flush completed buckets to the hub as one `burst_observed` event.
- [x] Bound the number of open burst buckets and count discarded groups under pressure.
- [x] Keep existing `ActivityAggregator` and persistence behaviour unchanged.
- [x] Compare live burst totals against the persisted activity chunk in tests.

### 10.4 Instrument low-volume stages

- [x] `dnsmasq.go`: emit after a query record is saved and after an answer materially changes it.
- [x] `conntrack.go`: change `upsertFlow` to report `recordID` and `created`; emit discovery only on creation and rate-limit update traces. _(Only the creation event is emitted; periodic counter updates are intentionally suppressed.)_
- [x] `correlator.go`: change attribution upsert to report whether a record was created/replaced; emit only on a material conclusion change.
- [x] `destination.go`: report create/refresh separately and emit destination enrichment only when durable data changes.
- [x] `destination.go`: emit route completion after `saveRoute` succeeds.
- [x] Emit a health event when packet capture starts, stops, drops events, or becomes incomplete.
- [x] Never let trace emission affect the observer return value or PocketBase save result.

### 10.5 Stream endpoint

Add:

```text
GET /api/infrareveal/debug/sessions/:sessionID/trace?after=<sequence>
```

SSE envelope types:

```text
hello      protocol version, session, oldest/newest sequence, server time
batch      ordered PipelineEvent[]
gap        requested/oldest/newest sequence and dropped count
status     hub ingress/subscriber drop counters
heartbeat  server time and newest sequence
```

- [x] Verify the session exists before opening the stream.
- [x] Reject tracing when `DEBUG_TRACE_ENABLED=false` with a clear `404` or feature-disabled response.
- [x] Follow PocketBase’s existing realtime route pattern: clear write deadline, set `text/event-stream`, `Cache-Control: no-store`, and `X-Accel-Buffering: no`.
- [x] Flush every envelope.
- [x] Exit on request context cancellation.
- [x] Enforce a maximum number of subscribers and return `503` when exceeded.
- [x] Filter every event by requested session before delivery.

**M5 tests**

- [x] Sequence monotonicity under concurrent observer emission.
- [x] Ring eviction by count and age.
- [x] Reconnect replay from an in-range sequence.
- [x] Explicit gap when reconnecting behind retention.
- [x] Slow subscriber cannot block a fast subscriber or ingress.
- [x] Burst coalescing totals and time boundaries.
- [x] Disabled mode has no route and no observer behaviour change.
- [x] SSE response terminates promptly when its request is cancelled.

---

## 11. M6 — Live trace frontend transport

### 11.1 Implement `TraceClient`

- [x] Use streaming `fetch()` rather than native `EventSource` so an operator bearer header can be added when required.
- [x] Parse SSE incrementally across arbitrary chunk boundaries.
- [x] Validate every envelope with the runtime decoder before touching state.
- [x] Store the last accepted sequence in memory per session.
- [x] Reconnect with bounded exponential backoff from 500 ms to 10 seconds.
- [x] Pass `after=<lastSequence>` when reconnecting.
- [x] Abort immediately when route/session/mode changes.
- [x] Never put the lab token in a URL, query string, log message, or local storage.

### 11.2 Merge ephemeral and durable data

- [x] De-duplicate live trace events by ID and sequence.
- [x] Prefer live `observed` timing over a later reconstructed `derived` event with the same stable identity.
- [x] Let durable records remain authoritative for labels, counters, and final session replay.
- [x] Remove ephemeral events only after their durable equivalent is visible or after retention expires.
- [x] On a gap envelope, show an unknown interval and trigger shared overview/detail reconciliation.
- [x] Do not synthesize missing packet activity as zero during a trace gap.

### 11.3 Live-edge behaviour

- [x] Compute trace live edge from the greatest accepted `occurredAtMs`, constrained by shared `serverNow` projection.
- [x] When following, seek Player to approximately 500 ms behind that edge.
- [x] Freeze the visual live edge if both trace and PocketBase realtime are unavailable.
- [x] Keep cached playback available while disconnected.
- [x] Display independent statuses for PocketBase data and trace stream so one cannot mask failure of the other.

**M6 tests**

- [x] Chunked SSE parsing, malformed envelopes, reconnect, abort, and gap handling.
- [x] Live event replaced by durable equivalent without duplicate tokens.
- [x] Reconnect does not reorder same-time events.
- [x] Scrubbing backward retains incoming events without moving the cursor.
- [x] Going live reaches the delayed edge in at most one shared clock tick.

---

## 12. M7 — Platform-independent gate controller core

Implement and test policy without requiring Linux or root. The Linux adapter should be a replaceable edge around this core.

### 12.1 Configuration

```text
LAB_GATE_ENABLED=false
LAB_GATE_QUEUE_NUM=42
LAB_GATE_STRICT_QUEUE_NUM=43
LAB_GATE_DNS_QUEUE_NUM=44
LAB_GATE_MAX_PENDING_FLOWS=128
LAB_GATE_MAX_HELD_PACKETS=768
LAB_GATE_FLOW_TIMEOUT_MS=10000
LAB_GATE_ESTABLISHED_TIMEOUT_MS=500
LAB_GATE_DNS_TIMEOUT_MS=2000
LAB_GATE_DECISION_CACHE_SECONDS=120
LAB_GATE_FAIL_OPEN=true
LAB_GATE_CONTROL_TOKEN_FILE=
LAB_GATE_ALLOWED_ORIGINS=
```

- [x] Refuse to enable real gating unless `LAB_GATE_ENABLED=true`.
- [x] Refuse to arm unless fail-open is enabled in the first implementation.
- [x] Refuse to arm if no control token is configured.
- [x] Validate queue numbers are distinct and in range.
- [x] Clamp pending/packet/time limits to safe configured bounds.
- [x] Log effective non-secret configuration; never log token contents.

### 12.2 Controller state machine

```text
OFF -> ARMING -> ACTIVE -> DRAINING -> OFF
                 |  |
                 |  +-> DEGRADED (fail-open, still observable)
                 +----> ERROR -> DRAINING
```

- [x] Serialize state transitions in one controller goroutine.
- [x] Require an active session ID and at least one validated client IP when arming flow mode.
- [x] Reject state-changing commands with `409` if they are invalid for the current state. _(The core returns typed `ErrInvalidTransition`; the M9 HTTP adapter maps it to 409.)_
- [x] `pause intake` accepts new packets immediately while retaining existing decisions.
- [x] `drain` accepts all held packets, closes their decisions as `drained`, and remains armed but paused.
- [x] `disarm` drains, clears client selection/cache, removes rule membership, and enters `OFF`. _(Selection is cleared in the core; M8 attaches it to the rule manager.)_
- [x] Any fatal queue error enters `DEGRADED`, releases what can be released, and exposes the error.
- [x] Shutdown always attempts drain before closing the queue handle.

### 12.3 Flow grouping

Maintain:

```go
pendingByDecisionID map[string]*Decision
decisionByFlowKey   map[string]string
packetToDecision    map[uint32]string
decisionCache       map[string]CachedVerdict
```

- [x] First unseen TCP SYN or UDP datagram creates one pending decision.
- [x] Retransmissions/additional pre-reply datagrams join the existing decision and increment packet count.
- [x] An already approved flow receives an immediate accept verdict while its decision cache entry is valid.
- [x] A rejected flow receives immediate drops while its rejection entry is valid.
- [x] Do not group different client source ports into one decision.
- [x] Store packet IDs and header summaries only; the adapter/kernel owns packet bytes.
- [x] Enforce both pending-flow and held-packet caps.
- [x] When caps are reached, immediately accept new packets, increment overflow, and emit/persist a `bypassed` event.

### 12.4 Verdict lifecycle

- [x] Apply the selected verdict to every packet currently attached to the decision.
- [x] Handle a packet arriving during verdict application without leaving it unowned.
- [x] Make repeated approve/reject requests idempotent and return the terminal result.
- [x] Default watchdog result is accept after the flow timeout.
- [x] Include `operator`, `watchdog`, `overflow`, `shutdown`, or `system` as the verdict source.
- [x] Publish `gate_waiting` and `gate_verdict` to `debugtrace` without blocking verdict application.
- [x] Queue audit persistence asynchronously after the kernel verdict is sent. _(The core only invokes the bounded `TryTerminal` edge after all verdict calls; M9 supplies the writer.)_

### 12.5 Abstract adapter

Define a fakeable boundary similar to:

```go
type PacketQueue interface {
    Start(context.Context, func(QueuedPacket)) error
    SetVerdict(packetID uint32, verdict Verdict) error
    Stats() QueueStats
    Close() error
}
```

- [x] Provide a deterministic fake queue for all policy tests and demo backend tests.
- [x] Simulate delayed duplicates, out-of-order callbacks, verdict errors, queue overflow, and shutdown races.
- [x] Prove no pending packet ID remains after drain/disarm in the fake.

**M7 tests**

- [x] Every valid and invalid state transition.
- [x] TCP/UDP grouping and decision caching.
- [x] Concurrent arrival during approve/reject.
- [x] Watchdog expiry and idempotent repeated decisions.
- [x] Flow and held-packet overflow fail-open paths.
- [x] Adapter verdict error enters degraded state and emits health information.
- [x] Shutdown drains all fake packets within a bounded test timeout.

---

## 13. M8 — Linux NFQUEUE and network-rule integration

Implementation evidence: `pocketbase/labgate/nfqueue_linux.go`, `pocketbase/labgate/firewall.go`, `entrypoint.sh`, and `scripts/test-lab-gate-netns.sh`. The privileged Linux namespace suite passed; see [local validation results](docs/validation/proxy-lab-local-results.md).

### 13.1 NFQUEUE adapter

- [x] Put the real implementation behind `//go:build linux`.
- [x] Configure copy mode to include at most the first 256 bytes needed by the bounded IP/transport parser.
- [x] Configure kernel queue max length explicitly and keep the controller held-packet cap below it.
- [x] Enable `NFQA_CFG_F_FAIL_OPEN`.
- [x] Record kernel/user drop counters where the library exposes them; otherwise read `/proc/net/netfilter/nfnetlink_queue` defensively.
- [x] Call controller ingress without blocking the NFQUEUE receive loop on PocketBase, SSE, or UI work.
- [x] Support asynchronous verdicts after the receive callback returns.
- [x] Treat malformed/unsupported packets as immediate accept with a visible parse/bypass counter.
- [x] Provide a non-Linux stub returning a typed `ErrUnsupported` while demo/passive UI remains usable.

### 13.2 Idempotent firewall chain

Refactor `entrypoint.sh` around a dedicated chain and IP set:

```text
INFRAREVEAL_LAB chain
infrareveal_lab_clients ipset

FORWARD position 1 -> INFRAREVEAL_LAB
INFRAREVEAL_LAB:
  selected client + outbound + conntrack NEW -> NFQUEUE 42 --queue-bypass
  RETURN
```

- [x] Install `ipset` in the runtime image only after dependency/system-package review.
- [x] Create chain/set with `-exist` semantics.
- [x] Insert exactly one jump before existing broad accept rules.
- [x] Keep the client set empty while the controller is off.
- [x] Add/remove clients through an argument-array command wrapper (`exec.CommandContext`), never an interpolated shell command.
- [x] Validate every IP with `netip.ParseAddr` before passing it to `ipset`.
- [x] Restrict the first version to the gateway’s configured IPv4 client subnet and say so in status.
- [x] Add IPv6 queue rules only if/when IPv6 forwarding is actually enabled by the gateway. _(IPv6 forwarding is not enabled, so no IPv6 queue policy is installed.)_
- [x] Delete the jump, flush/delete the chain, and destroy the set during cleanup.
- [x] Make cleanup succeed when resources are already absent.

### 13.3 Correct process and signal handling

The current shell starts the PocketBase binary in the foreground and refers to `CHILD` later. Refactor as part of lab safety:

- [x] Start `/root/pb/infra-reveal serve ...` in the background and assign `CHILD=$!` before `wait`.
- [x] On `SIGTERM`/`SIGINT`, request/allow controller drain, remove lab rules, terminate the child, and wait for it.
- [x] Keep existing DNS/NAT/AP cleanup intact and idempotent.
- [x] Ensure an unset child PID can never be passed to `kill`.
- [x] Prefer `exec` only if all network-rule cleanup moves into the Go process with equivalent guarantees. _(The background-child design is retained because shell cleanup remains necessary.)_
- [x] Add `shellcheck` validation and a test harness that stubs `iptables`, `ipset`, and service commands.

### 13.4 Startup order

- [x] Create NFQUEUE resources with `--queue-bypass` before the listener is ready.
- [x] Start the queue listener before allowing any client into the IP set.
- [x] Report `supported`, `listenerReady`, `rulesReady`, and `armed` separately.
- [x] If the kernel module/library initialization fails, leave the client set empty and expose passive-only status.
- [x] Never make container startup fail solely because optional lab mode is unsupported when `LAB_GATE_ENABLED=false`.

**M8 Linux integration test**

- [x] Add a privileged script under `scripts/` that creates client/gateway/upstream network namespaces with veth pairs.
- [x] Verify off mode forwards without entering an active NFQUEUE listener.
- [x] Verify an armed TCP SYN remains pending until accept.
- [x] Verify accept completes the connection and reject fails it.
- [x] Verify UDP packets group by tuple. _(Covered by the real adapter parser plus controller grouping tests.)_
- [x] Kill the controller and verify `--queue-bypass`/fail-open preserve forwarding.
- [x] Fill the queue deliberately and verify overflow accepts rather than drops.
- [x] Run cleanup twice and verify no chain, jump, set, or namespace remains.

---

## 14. M9 — Control APIs and durable auditing

Implementation evidence: `pocketbase/labgate/routes.go`, `pocketbase/labgate/audit.go`, migrations `202609030001`–`202609030003`, and the shared `gateEvents` entity/index path. Route, audit, migration-smoke, paging, and realtime tests pass; see [local validation results](docs/validation/proxy-lab-local-results.md).

### 14.1 Authentication and request policy

- [x] Load a random operator token from `LAB_GATE_CONTROL_TOKEN_FILE`; refuse mutating lab mode without it.
- [x] Accept the token only through `Authorization: Bearer ...`.
- [x] Compare tokens in constant time.
- [x] Do not accept token query parameters.
- [x] Keep the token in frontend memory only; clear it on route exit/refresh.
- [x] Restrict CORS to configured debug-dashboard origins.
- [x] Require JSON content type on mutations.
- [x] Add request body limits and strict JSON decoding.
- [x] Rate-limit failed authentication and mutating commands.
- [x] Record actor as a non-secret stable operator label supplied after authentication, with a safe fallback.

### 14.2 Status and reconciliation endpoints

```text
GET  /api/infrareveal/lab-gate/status
GET  /api/infrareveal/lab-gate/pending
POST /api/infrareveal/lab-gate/arm
POST /api/infrareveal/lab-gate/pause
POST /api/infrareveal/lab-gate/resume
POST /api/infrareveal/lab-gate/drain
POST /api/infrareveal/lab-gate/disarm
POST /api/infrareveal/lab-gate/decisions/:decisionID
POST /api/infrareveal/lab-gate/approve-all
```

- [x] `status` reveals feature/support/health but no secret and may be readable without the control token.
- [x] All other endpoints require the bearer token.
- [x] `arm` body requires active `sessionId`, mode, client IPs, and optional strict tuple.
- [x] Verify every client belongs to the configured client subnet and ideally the current DHCP lease/client list. _(Subnet validation is mandatory; the live session-derived client picker provides the additional operator-side constraint.)_
- [x] Reject recorded/inactive sessions.
- [x] Return `404` for unknown decision IDs, `409` for stale/terminal decisions, and `503` when the kernel controller is unavailable.
- [x] Return the full resulting `GateStatus` after every successful mutation so the UI can reconcile immediately.
- [x] Give every response a request/command ID for audit correlation.

### 14.3 Gate-event migration and writer

- [x] Create the `gate_events` collection with the contract in section 4.3.
- [x] Add API rules and indexes.
- [x] Implement an async audit writer with a bounded buffer separate from the verdict path.
- [x] Give that writer sole ownership of persistence ordering for each decision so a terminal update cannot race ahead of the initial record creation.
- [x] Write the initial `queued` record without delaying packet reception; update terminal state after verdict.
- [x] Retry transient PocketBase save failures with a bounded backoff.
- [x] If auditing is unavailable, continue fail-open operation but show a prominent degraded/audit-loss status.
- [x] Count lost audit events and never report the audit trail as complete when loss occurred.
- [x] Add gate events to `clearObservationCollections` and session retention/deletion behaviour.

### 14.4 Session runtime integration

- [x] Extend `SessionWindow`, `GatewayData`, entity maps, ownership, indexes, byte estimation, selectors, and realtime mapping with gate events.
- [x] Include gate events in overview only as counts/terminal markers if detailed rows would exceed page limits.
- [x] Fetch full gate detail through bounded window pages.
- [x] Reconcile missed create/update events after realtime reconnect.
- [x] Keep both existing dashboards compiling even when they ignore `gateEvents`.

### 14.5 Wire the gate into PocketBase lifecycle

- [x] Parse lab-gate configuration and create either the real Linux adapter or the unsupported/no-op adapter in `pocketbase/main.go`.
- [x] Start the queue listener before registering any client in the lab IP set.
- [x] Register status/control routes with the controller instance rather than global mutable variables.
- [x] Provide the controller a callback that validates the requested session against PocketBase’s active session.
- [x] On session deactivation, trigger controller drain/disarm before observers switch to the next session.
- [x] On `OnTerminate`, stop new intake, drain held packets, stop the audit writer, and then cancel observer/trace contexts.

**M9 tests**

- [x] Auth missing/invalid/valid, origin policy, body limit, and malformed JSON.
- [x] Active-session and client-subnet validation.
- [x] Idempotent command responses and error status codes.
- [x] Migration up/down and immutable client rules.
- [x] Audit queue failure cannot delay or reverse a kernel verdict.
- [x] Session window pagination/realtime reconciliation includes gate events correctly.

---

## 15. M10 — Real turn-based UI integration

Implementation evidence: `debug-dashboard/src/experiments/proxy-lab/data/gateClient.ts`, `GateArmDialog.tsx`, `QueueInspector.tsx`, `GateHealth.tsx`, and `/controlled-client`. TypeScript tests/build/lint and Chromium desktop/narrow interaction pass; see [local validation results](docs/validation/proxy-lab-local-results.md).

### 15.1 Gate client

- [x] Implement typed functions for every status/control endpoint.
- [x] Centralize bearer injection and error decoding.
- [x] Abort in-flight status/pending requests when session changes.
- [x] Reconcile `pending` after reconnect and after every command.
- [x] Never optimistically remove a queue item before the backend confirms the terminal verdict.
- [x] Treat a `409` stale decision as a prompt to refresh status, not a generic fatal error.

### 15.2 Arming flow

- [x] Show passive capability/status before asking for a token.
- [x] Require a deliberate `Arm lab gate` action; selecting the tab alone must not alter traffic.
- [x] In the arm dialog show:
  - active session;
  - chosen clients;
  - flow vs strict mode;
  - fail-open policy;
  - queue/time limits;
  - protocols not covered;
  - an explicit acknowledgement that client traffic will be delayed.
- [x] Require at least one selected client in flow mode.
- [x] Require exactly one client plus a complete tuple in strict mode.
- [x] Show ARMING until listener/rules/client membership are confirmed.

### 15.3 Approval queue

- [x] Sort pending decisions by `queuedAt`, oldest first.
- [x] Display client, protocol, destination IP/port, source port, best known hostname, packet count, TCP flags, wait time, and watchdog deadline.
- [x] Label hostname confidence and retain raw IP.
- [x] Group retransmissions visually under their decision.
- [x] Provide Approve and Reject per decision.
- [x] Provide Approve all only with a confirmation showing item count.
- [x] Provide Pause intake, Drain, and Disarm as separate concepts.
- [x] Disable actions while the matching command is in flight, not the entire queue.
- [x] Announce terminal results through an accessible live region.
- [x] Move decided items into a short recent-history section before they disappear.

### 15.4 Safety/health UI

- [x] Always show OFF/ARMING/ACTIVE/PAUSED/DRAINING/DEGRADED/ERROR.
- [x] Display kernel queue depth, held packets, pending flows, ingress drops, hub drops, audit drops, oldest wait, and watchdog releases.
- [x] Make fail-open bypasses amber/red events, never green approvals.
- [x] Keep an emergency Disarm action visible without scrolling.
- [x] Poll status slowly as reconciliation even while trace streaming is healthy.
- [x] If trace streaming fails, keep controls functional through HTTP and label the graph stale.
- [x] If control API fails, stop presenting queue items as actionable.

### 15.5 Client-visible validation

- [x] Add a small controlled test page/client that starts fetches with configurable application timeouts.
- [x] Show request start, completion/failure, measured wait, and configured repeated attempts; explicitly disclose that browser-internal retries are not exposed.
- [ ] Test TCP, UDP/QUIC-capable browser behaviour, and hostname/IP requests separately on target clients. _(Client-matrix validation pending.)_
- [x] Treat alternate connection attempts and fallbacks as new linked flows, not duplicates to hide.

**M10 exit criteria**

- [ ] An operator can arm one physical Wi-Fi client, see its new flow pause, approve it, and watch the client continue. _(Target Pi acceptance pending; kernel hold/accept passes in namespaces.)_
- [ ] Reject visibly fails the selected physical-client attempt and records a terminal event. _(Target Pi acceptance pending; kernel rejection and audit tests pass independently.)_
- [x] Watchdog release works with the UI closed.
- [x] Disarm restores normal traffic without restarting the container.

---

## 16. M11 — Strict packet and DNS diagnostic modes

These modes intentionally have narrower support and stronger warnings. Their code is complete, but they must remain disabled in operational use until flow mode and target hook ordering pass the Raspberry Pi failure tests.

Implementation evidence: strict and DNS queues use isolated queue numbers and rules in `pocketbase/labgate`, with exact-rule, parser, grouping, watchdog, packet-step, and automatic-disarm tests. The UI exposes both modes and the runbook contains controlled presets. Physical target DNS/client outcomes remain in M12.

### 16.1 Strict one-flow packet stepping

- [x] Require exactly one client IP, protocol, client port, remote IP, and remote port.
- [x] Install queue 43 matching both directions before the existing inbound established accept rule.
- [x] Queue only the exact tuple; all unrelated traffic bypasses.
- [x] Display individual packet direction, timestamp, wire size, payload size, and TCP flags.
- [x] Never display or persist payload contents.
- [x] Allow one-packet Accept, Drop, Accept next N, and Drain flow.
- [x] Enforce the 500 ms default watchdog; the controlled client can configure its application timeout but cannot weaken the kernel safety watchdog.
- [x] Cap visible/pending strict packets well below the kernel queue capacity.
- [x] Refuse strict mode for multiple clients or wildcard tuples.
- [x] Display retransmissions as separate packets because they are the point of this mode.
- [x] Automatically disarm strict mode when the selected flow terminates or the session ends.

### 16.2 DNS input gate

DNS currently redirects to local dnsmasq, so add a separate guarded INPUT rule using queue 44.

- [ ] Match only selected client traffic arriving on `AP_IFACE` for UDP/TCP destination port 53 after confirming actual hook ordering on the target. _(The exact isolated rules are implemented and unit-tested; physical target hook-order confirmation remains.)_
- [x] Gate UDP DNS datagrams and TCP DNS connection establishment separately.
- [x] Do not parse/persist DNS payload in the gate; label pending items by client/protocol and link a later dnsmasq observation by client and time.
- [x] Default watchdog accept after two seconds.
- [x] Group duplicate UDP retries by client transport tuple where safe; transaction IDs are intentionally unavailable because payloads are not inspected.
- [x] Never gate DHCP, gateway API, or operator UI traffic.
- [x] Make DNS gating a separate opt-in toggle from forwarded-flow gating.
- [x] Visualize the path as client → wlan0 → DNS gate → dnsmasq, not through NAT/Internet until dnsmasq forwards upstream.

### 16.3 Timeout-oriented scenarios

- [x] Add documented presets:
  - `Visible pause` — flow gate, 3-second suggested decision window.
  - `Retry demonstration` — controlled client, hold past first RTO.
  - `DNS retry` — DNS gate, release before safety timeout.
  - `Strict handshake` — exact TCP tuple, packet stepping.
- [x] Disable QUIC in the controlled browser scenario when demonstrating TCP handshake mechanics.
- [x] Provide a one-address-family scenario when avoiding Happy Eyeballs is important.
- [x] Explicitly state that the gateway cannot pause arbitrary client application timers.

**M11 tests**

- [x] Exact tuple rule catches both directions and no neighbouring flow.
- [x] Strict-mode watchdog prevents indefinite kernel retention.
- [ ] DNS query waits, is approved, reaches dnsmasq, and produces the normal DNS record on the target Pi.
- [ ] DNS rejection produces client retry/failure without breaking other physical clients.
- [x] Dashboard/control traffic is excluded by both rule sets; target reachability remains part of the Pi drill.

---

## 17. M12 — Validation, performance, privacy, and failure testing

Local validation evidence is recorded in [docs/validation/proxy-lab-local-results.md](docs/validation/proxy-lab-local-results.md). Unchecked items below require the physical Raspberry Pi, real Wi-Fi clients, or a sustained 60-minute run and are intentionally not claimed as complete.

### 17.1 Automated test matrix

- [x] Frontend:

  ```bash
  pnpm --filter @infrareveal/session-state test
  pnpm --filter @infrareveal/debug-dashboard test
  pnpm --filter @infrareveal/debug-dashboard build
  pnpm --filter @infrareveal/debug-dashboard lint
  ```

- [x] Backend:

  ```bash
  cd pocketbase
  go test ./...
  go test -race ./debugtrace ./labgate ./netmeta
  ```

- [x] Workspace:

  ```bash
  pnpm test
  pnpm build
  pnpm lint
  docker compose build proxy dashboard
  ```

- [x] Linux-only privileged namespace integration suite. _(Passed in a disposable privileged Linux container.)_
- [x] Shellcheck and idempotent startup/cleanup harness.
- [x] Migration test starting from a copy of existing PocketBase data.

### 17.2 Determinism and replay

- [x] Snapshot selected frames from the same fixture twice and compare output. _(Consecutive 1440×1000 captures were byte-identical.)_
- [x] Verify rate changes do not change which events exist at a given cursor.
- [x] Verify live-origin events and later durable reconstruction render identically where timestamps are known.
- [x] Verify unknown/incomplete periods remain marked across all LOD levels.
- [x] Verify recorded sessions never advance their live edge.

### 17.3 Thirty-client, 60-minute soak

- [ ] Generate representative concurrent browsing, video, messaging, idle background, DNS, and QUIC traffic.
- [ ] Capture baseline gateway CPU, memory, packet loss, latency, and throughput with debug trace disabled.
- [ ] Repeat with passive trace enabled and no browser connected.
- [ ] Repeat with one and several debug viewers.
- [ ] Confirm hub, subscriber, frontend ring, token count, shared detail cache, and PocketBase storage are bounded.
- [ ] Confirm there is no monotonic memory growth after the warm-up period.
- [ ] Confirm passive trace adds no forwarding-path wait and keeps latency/throughput within the agreed regression budget.
- [ ] Record all trace drops and verify the UI shows the corresponding incomplete interval.

### 17.4 Gate load and failure drills

- [ ] Arm one client while 29 other clients bypass; verify no measurable disruption to bypass clients.
- [x] Arm several simulated clients until the pending-flow cap is reached; verify new flows fail open.
- [x] Fill the held-packet cap; verify immediate bypass and visible overflow events.
- [x] Close the browser while packets wait; verify watchdog releases them. _(The controller owns the watchdog independently of browser state.)_
- [x] Kill the Go process; verify queue bypass preserves forwarding. _(Passed with a held packet in the Linux namespace suite.)_
- [x] Send SIGTERM to the container; verify drain and firewall cleanup. _(Signal/cleanup harness plus controller shutdown tests.)_
- [x] Disconnect/reconnect PocketBase storage; verify kernel verdicts continue and audit degradation is visible. _(Persistence-failure path is injected in the audit/controller tests.)_
- [ ] Remove/rename the AP interface; verify the controller degrades without unsafe partial arming.
- [x] End the active session while armed; verify automatic drain/disarm.
- [ ] Reboot the Pi after an unclean stop; verify startup removes stale lab chains/sets before recreating them. _(Idempotent recreation is unit/harness-tested; physical reboot remains.)_

### 17.5 Privacy and security review

- [x] Search schemas, logs, API fixtures, and trace envelopes for raw payload buffers.
- [x] Verify only the bounded parser sees packet prefixes and does not retain references after classification.
- [x] Verify bearer tokens never appear in browser URL/history, PocketBase records, application logs, screenshots, or exceptions.
- [x] Verify unauthorized clients on the open AP cannot arm, approve, reject, drain, or disarm the gate.
- [x] Verify list/view permissions for gate events match the consent/session data model.
- [x] Add explicit UI copy that this is a traffic-changing lab experiment.
- [x] Add audit-loss and fail-open disclosures to exported/recorded sessions.

### 17.6 Browser and client matrix

- [x] Chromium desktop.
- [ ] Firefox desktop.
- [ ] Safari desktop/iOS.
- [ ] Android Chromium.
- [x] Controlled Linux CLI client using curl in isolated network namespaces.
- [ ] Record differences in DNS resolver behaviour, QUIC fallback, Happy Eyeballs, and application timeouts.

**M12 exit criteria**

- [x] All automated suites pass.
- [ ] The target Pi passes passive and gate soak/failure testing.
- [x] No payload persistence or control-auth vulnerability remains open in the implemented contract and test suite.
- [x] Measured limitations are visible in the UI and documentation.

---

## 18. M13 — Documentation and operational handoff

Handoff evidence: [implementation guide and runbook](docs/implementation-guides/proxy-lab.md), [ADR 0002](docs/adr/0002-opt-in-nfqueue-flow-admission.md), [target validation procedure](docs/validation/proxy-lab-raspberry-pi.md), and [completed local validation](docs/validation/proxy-lab-local-results.md).

### 18.1 Repository documentation

- [x] Add a README section explaining passive trace vs lab gate.
- [x] Add every new environment variable with default, bounds, and safety effect.
- [x] Document required kernel modules/packages and the runtime capability check.
- [x] Add `docs/implementation-guides/proxy-lab.md` covering architecture and event semantics.
- [x] Add `docs/validation/proxy-lab-raspberry-pi.md` with the exact namespace/Pi/manual test procedure.
- [x] Add an ADR for opt-in NFQUEUE flow admission, including why flow-level approval was chosen over all-packet approval.
- [x] Update the existing metadata-gateway ADR only by linking the new lab-mode ADR; do not weaken the passive production decision.

### 18.2 Operator runbook

- [x] How to generate/store the control token.
- [x] How to enable passive tracing only.
- [x] How to enable lab support without arming a client.
- [x] How to arm selected clients.
- [x] How to interpret queue, drop, bypass, watchdog, and audit counters.
- [x] How to drain/disarm through UI and command line.
- [x] How to remove stale iptables/ipset resources manually.
- [x] How to verify normal forwarding after the experiment.
- [x] Emergency recovery steps when the UI is unavailable.

### 18.3 Final handoff

- [x] Update every checkbox in this plan to reflect actual completion.
- [x] Link tests and validation evidence beside the corresponding milestone.
- [x] Re-render/revise `implementation-plan.html` if the final UI differs materially from the approved concept.
- [x] Confirm `git status` contains only intended implementation changes.
- [x] Provide the user with routes, configuration, test results, known limitations, and a safe first-run procedure.

---

## 19. Suggested implementation/commit sequence

Keep each step independently buildable and revertible:

1. **chore: update workspace and Go dependencies**
2. **refactor(debug-dashboard): add experiment routes**
3. **refactor(observer): share canonical flow identity**
4. **feat(debug-dashboard): project recorded proxy pipeline**
5. **feat(debug-dashboard): add deterministic Remotion pipeline scene**
6. **feat(proxy): stream bounded passive debug traces**
7. **feat(debug-dashboard): follow live pipeline traces**
8. **feat(proxy): add tested flow-gate controller core**
9. **feat(proxy): add guarded Linux NFQUEUE adapter**
10. **feat(proxy): add gate APIs and audit events**
11. **feat(debug-dashboard): add real queue controls and health UI**
12. **feat(proxy-lab): add strict flow and DNS modes**
13. **test(proxy-lab): add Pi soak and failure validation**
14. **docs: add proxy-lab ADR, guide, and runbook**

Do not combine steps 1, 6, and 9 into one change. Dependency risk, passive observability risk, and traffic-changing kernel integration need separate review and rollback points.

---

## 20. Timeout assumptions and test budgets

These values guide safe defaults; they are not guarantees for every phone, browser, SDK, operating system, or remote service. The gateway can control its own queue/watchdog and conntrack settings, but it cannot pause client-side clocks.

| Mechanism | Reference behaviour | Implication for implementation |
| --- | --- | --- |
| Linux NFQUEUE | Current kernel default queue length is 1,024 packets; a full queue drops unless fail-open is enabled. See [Linux `nfnetlink_queue.c`](https://github.com/torvalds/linux/blob/master/net/netfilter/nfnetlink_queue.c) and [libnetfilter_queue](https://netfilter.org/projects/libnetfilter_queue/doxygen/html/). | Keep the controller cap below the kernel cap, enable fail-open, and expose both kernel and controller drops/bypasses. |
| Linux TCP connect | Initial retransmission is roughly one second; the upstream default of six SYN retries results in a final active-connect timeout around 131 seconds. See [Linux IP sysctls](https://docs.kernel.org/networking/ip-sysctl.html). | A human-visible hold causes retransmissions well before the socket finally fails. Group those retransmissions under one flow decision. |
| Happy Eyeballs | A recommended default starts the next candidate after 250 ms. See [RFC 8305](https://www.rfc-editor.org/rfc/rfc8305.html). | A browser may create a second IPv4/IPv6 flow while the first is held. Link it as a related attempt; do not hide it as a duplicate. |
| glibc DNS | Default resolver timeout is currently five seconds with two attempts, but a call can take a different total time. See [`resolv.conf(5)`](https://man7.org/linux/man-pages/man5/resolv.conf.5.html). | Use a two-second DNS watchdog as a conservative starting point and validate actual mobile resolvers separately. |
| QUIC | Without an RTT sample, initial handshake PTO is normally one second and backs off exponentially. See [RFC 9002](https://www.rfc-editor.org/rfc/rfc9002.html). | Holding UDP/443 will produce probes and may trigger TCP fallback; both are useful trace events but make “one request” an unsafe label. |
| DHCP | Suggested first retry is approximately four seconds, then eight seconds, doubling up to 64. See [RFC 2131](https://www.rfc-editor.org/rfc/rfc2131.html). | DHCP must bypass the gate so clients remain attached and the operator can recover the experiment. |
| Conntrack | Upstream defaults include TCP SYN-sent 120 s, SYN-received 60 s, UDP 30 s, UDP stream 120 s, and established TCP five days. See [conntrack sysctls](https://docs.kernel.org/networking/nf_conntrack-sysctl.html). | These are gateway bookkeeping lifetimes, not application patience. Do not derive watchdog deadlines from conntrack expiry. |
| HTTP/TLS/application | There is no universal request/handshake timeout shared by clients and servers. | Test representative real clients and use a custom client for intentionally long strict-mode demonstrations. |

- [x] At startup, read and expose relevant target-kernel queue/conntrack settings without mutating them automatically.
- [x] Record the effective gate watchdog deadlines in `GateStatus` and every pending decision.
- [x] Warn the operator before a decision reaches 50% and 80% of its watchdog budget.
- [x] Treat watchdog accept as `expired`, not as an operator approval.
- [ ] Verify the three-second visible-pause scenario on every supported client category.
- [x] Use the controlled client for any scenario intended to exceed normal resolver/application patience.
- [x] Document observed platform deviations instead of changing global defaults to fit one client.

---

## 21. Final definition of done

- [x] `/proxy-lab/:sessionID` replays old and new recorded sessions using the shared session clock.
- [x] The same route follows an active session, scrubs backward, and returns to live.
- [x] Slow motion and frame/event stepping are deterministic.
- [x] Data-plane and observation-plane events are visually and semantically distinct.
- [x] Live trace load is coalesced, bounded, reconnectable, and honest about gaps.
- [x] Normal gateway mode installs no effective queue policy and forwards as before.
- [x] Lab mode can hold, approve, reject, expire, drain, and audit selected new flows.
- [x] Controller/browser/storage failure cannot silently strand all client traffic.
- [x] Strict packet and DNS modes enforce their narrower safety bounds.
- [ ] Thirty-client/60-minute validation passes on the target Raspberry Pi.
- [x] No packet payload or control token is persisted.
- [x] Production dashboard build/tests remain green and contain no lab experiment UI.
- [x] Documentation lets another operator enable, demonstrate, and recover the feature safely.
