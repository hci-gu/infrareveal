# Traceroute rewrite plan

Status: proposed, 17 September 2026. This is an implementation plan, not a claim that the deployed failure has been reproduced or fixed.

Superseded for implementation by [implementation-plan.md](../../implementation-plan.md). The updated plan prioritizes a small number of useful visual route approximations, hard limits on automatic work and storage, and elimination of duplicate/status-only route records. Its collection, persistence, retry and rollout decisions take precedence over the broader proposal below.

Replace route discovery with an evidence-based measurement module: observe the real remote endpoint, measure a synthetic gateway flow with a controlled probe engine, retain the responses and measurement limits, and derive network and geographic explanations separately. The product must provide useful endpoint and network information even when intermediate routers remain silent.

The main input is [deep-research-traceroute.md](../../deep-research-traceroute.md). The plan also reflects the current code, [ADR 0001](../adr/0001-metadata-gateway-not-transparent-tls-proxy.md), [ADR 0002](../adr/0002-opt-in-nfqueue-flow-admission.md), and the existing [implementation](../implementation-guides/live-route-discovery.md) and [validation](../validation/live-route-discovery.md) guides. Those ADRs remain valid: normal client forwarding is independent of measurement.

## 1. What the research changes—and what already exists

The research correctly distinguishes actual endpoint observations, responding IP interfaces, inferred routers/networks, and uncertain physical geography. It does not establish why this deployment reports almost exclusively missing hops. Its assumed DNS → traceroute pipeline also differs from the current production implementation.

| Area | Current repository evidence | Rewrite decision |
| --- | --- | --- |
| Target discovery | `observer/conntrack.go` already submits committed flows to `routing.Observe`, using observed IP/protocol/port. | Preserve this. Extend measurement context; do not rebuild discovery around DNS. |
| Fast measurement | `routing/probe.go` runs Linux traceroute with one probe per TTL, eight outstanding probes, 500 ms waits, 40 ms spacing and a three-second deadline. | Replace as the authoritative engine. Keep the executable for independent diagnostics during migration. These settings can constrain visibility; they are not a proven explanation for the reported rate. |
| Coverage measurement | `routing/coverage.go` already uses Scamper TCP, UDP Paris and ICMP Paris, with retries. It starts a separate process for every four-TTL range and appends their outputs into one attempt. | Use one engine measurement across the TTL range. A repeated source identifier across processes is insufficient verification of all relevant on-wire fields and reply matching. |
| Cancellation | Coverage retains completed ranges, but breaks on process error before decoding returned data from the current range. | Preserve every validated result received before cancellation; distinguish an unfinished measurement from a silent router. |
| Result semantics | `Hop` combines `Missing`, free-form `State`, one primary address and optional replies. The coordinator increments failure counters for every non-reached terminal attempt. | Separate execution outcome, endpoint response, TTL observations and interpretation. Ordinary silence is not an engine failure. |
| Evidence selection | `betterSnapshot` compares destination reached, reply coverage, located hops and recency across attempts/methods. | Separate freshness, method compatibility and historical richness. Geography must not decide which path is current. |
| Enrichment | GeoIP is applied directly to primary hop addresses in `routing/storage.go`; other responders are not individually enriched. No explicit special-address exclusion exists there. | Enrich each responding interface separately, behind a shared address classifier. Add prefix/ASN context and provenance. |
| Address scope | `observer/scope.go` uses a client string prefix, normally `10.0.0.`; its public-address check does not exclude CGN shared space. `entrypoint.sh` configures IPv4 forwarding/NAT. | Make client scope CIDR-based and family-aware. Treat dual-stack deployment as a separate acceptance requirement, not just an engine option. |
| Persistence/playback | Immutable route observations, network-scoped reuse, session revisions, availability times, invalidation and bounded history already exist. | Preserve these contracts and version their payloads. |
| Presentation | Main map already retains unknown spans. Some debug consumers still select by IP or IP+port and label routes complete/incomplete. | Move every consumer onto shared typed selection and explanations; add a topology view independent of coordinates. |
| Legacy implementation | `lib/traceroute.go` still contains hostname probing, star removal, duplicate-hop removal and airport-code guessing. References remain in old proxy/debug code in `main.go`; normal startup uses the metadata observers. | Remove executable legacy paths after a caller audit; preserve historical records through a read adapter. |

The reported **99.9%** needs a denominator: probes, attempted TTL positions, route attempts, flows, or UI rows. The existing validation guide describes a different, older sample with 23 responding positions out of 137 and five reached TCP destinations. That does not disprove the current report; it means the samples cannot be equated. The documented probe/capture comparison on the affected uplink was never completed.

## 2. Product contract

For a selected flow, answer these questions independently:

1. Which remote IP, port, transport and address family did the gateway observe, and when? Show sampled connection activity; do not equate a conntrack entry with successful HTTPS or application delivery.
2. What did gateway-originated probes observe toward that endpoint, using which method and source context?
3. Which TTL positions returned responses, which timed out, and which were never measured or remain indeterminate?
4. Which networks are associated with responding IP prefixes, and what location hypotheses are supported?
5. How old is each item of evidence, and what changed between comparable measurements?

A gateway probe is a different flow from the client's connection. NAT, source-port selection, policy routing, ECMP, DSCP, IPv6 flow labels and timing can change its path. Preserve the observed client tuple as attribution context, record the probe tuple separately, and label the relationship **gateway approximation**. Do not inject probes into a live client tuple or claim exact application-flow replay.

UDP/443 indicates a transport/port observation, not confirmed QUIC. A generic UDP Paris probe is not a valid HTTP/3 exchange; lack of a destination response is inconclusive. TCP responses likewise establish probe behavior, not successful application service.

The primary useful result can be “observed endpoint and destination network; two responding TTL positions; intermediate path unobserved.” Neither an ASN sequence nor a physical route can be reconstructed reliably by filling silent sections with guesses. An adjacent pair of responding TTL positions describes logical measurement order, not a verified physical cable.

## 3. Establish the failure mechanism first

Extend `route-diagnose` and its namespace harness before changing the default engine. The current diagnostic uses four Linux traceroute profiles; it does not exercise the actual Scamper coverage implementation.

Run a reproducible comparison against IPs and ports from fresh observed flows, on the affected Pi/uplink. Include TCP, UDP and ICMP, and each configured address family. Compare the deployed fast profile, deployed Scamper profile, and candidate engine with similar packet/time budgets. Record gateway build, exact executable versions, source address, selected egress route/interface, network context and concurrent measurement load.

Collect bounded, measurement-specific header metadata at these seams:

- Probe requested and engine accepted it.
- Probe transmitted, where observable; distinguish engine-reported transmission from capture-confirmed transmission.
- Matching ICMP error or terminal transport response arrived at the interface.
- Engine matched/classified the response and emitted structured output.
- Backend normalized, persisted and published it.
- Browser selected and rendered the correct revision.

Capture TCP terminal replies as well as ICMP/ICMPv6. Correlate quoted packets to the probe identity, not only the remote address. Make IPv6 parsing extension-header-aware; the current diagnostic filter assumes fixed offsets. Report capture drops, truncation and receiver readiness so a broken diagnostic cannot masquerade as upstream silence. Retain only required probe headers and bounded raw measurement output, not client application payloads.

| Comparison result | Interpretation and next action |
| --- | --- |
| Requested probe never transmits | Investigate engine capability, privileges, source route, budget or local send error. |
| Matching reply captured, absent from engine output | Investigate local filtering, engine matching, packet format or executable defect. |
| Reply in structured output, absent from stored evidence | Fix decoder, validation, cancellation or persistence. |
| Correct stored evidence, absent/mislabeled in UI | Fix route binding, time selection or presentation. |
| Confirmed sends, healthy capture, no matching returns | Visibility limit under the tested conditions; upstream filtering, suppression and loss remain hypotheses. |
| Destination responds after silent TTLs | Keep the endpoint response and explicit silent positions. Do not call the route broken. |

Deliver a small fixture corpus and a diagnostic report with explicit denominators. Do not make an Internet hop-response percentage the acceptance condition for software correctness.

## 4. Target modules and ownership

```text
Observed client flows + observed DNS evidence
                  |
                  v
Route demand and measurement policy
                  |
                  v
Scamper adapter -> immutable measurement observations
                              |
                    +---------+----------+
                    |                    |
              IP/network evidence   location/alias evidence
                    |                    |
                    +---------+----------+
                              |
                   immutable session route revisions
                              |
                  shared selection and explanation
                              |
                  topology view / map / diagnostics
```

Keep `pocketbase/routing` as the owning module with the existing `Observe`, `Status` and `Reset` interface. Its implementation owns demand, scheduling, engine lifecycle, evidence persistence and publication. The engine adapter hides process/control protocol, structured decoding and cancellation behind one tested seam. A replay adapter supplies recorded engine fixtures to the same interface.

Add one IP evidence module for address classification, prefix/ASN lookup, PTR and location hypotheses, shared by destination and responding-interface enrichment. It owns caching, source versions and inference rules; callers should not choose a GeoIP fallback algorithm. Keep network enrichment asynchronous from measurement and forwarding.

The shared session module owns route selection, state labels, counts and logical topology projection. Dashboard-specific rendering remains outside it. This gives locality to measurement semantics and prevents each inspector from defining its own meaning of “missing.” Avoid a framework of one-function wrappers: the leverage comes from concentrating complete behavior behind these interfaces.

## 5. Replace the measurement engine

Use a pinned, capability-tested Scamper build as the primary adapter. Support ARMv7 and ARM64 in the actual Debian runtime. Keep one logical trace task for the complete TTL range; remove the four-TTL subprocess assembly and ordinary-traceroute foreground/Scamper-repair split.

Scamper supports controlled-rate IPv4/IPv6 measurements and dynamic task submission through a control socket. Its native warts format retains detailed measurement metadata. These capabilities suit the proposed adapter; the exact deployed build still needs qualification. [CAIDA Scamper overview](https://www.caida.org/catalog/software/scamper/)

Preferred implementation: one supervised process controlled through a local Unix socket, with a bounded decoder/output stream. Pin the matching decoder and engine versions. Keep PocketBase's Go build independent of C libraries by placing any native-format conversion in the external adapter process/toolchain. Do not implement a second raw-socket traceroute stack in Go.

The current official manual documents `trace -y` for in-progress results and `halt` for control-mode cancellation. Qualify those capabilities in the selected release rather than assume the Bookworm package supports them. Preserve progress from one task; verify cumulative versus incremental records, duplicate handling and stop semantics. [Scamper manual](https://www.caida.org/catalog/software/scamper/man/scamper.1.pdf)

If a qualified build cannot provide progressive observations, publish honest running state and the complete task result. Do not manufacture progressive hops by joining independent traces. A bounded command-process adapter can support the same interface until control-mode integration qualifies; the single-task and provenance requirements still apply.

| Observed transport | First method | Bounded comparison methods |
| --- | --- | --- |
| TCP | TCP SYN to observed destination port | ICMP Paris, then UDP Paris if justified |
| UDP | UDP Paris to observed destination port | ICMP Paris; optional TCP on a separately labeled comparison port |
| Other/unsupported | Explicit capability result | ICMP Paris only when policy permits a transport mismatch |

Keep flow-selection fields stable within each trace, with collision-free allocation and a hold-down for late replies. Individual probes still need distinct correlation identifiers that preserve the method's intended flow behavior. Record source address/port or ICMP identifier, destination, method, packet size, DSCP and IPv6 flow label where supported. Verify on-wire constancy and reply matching in the namespace fixture. TCP's flow behavior must be tested rather than labeled Paris solely because a fixed port was requested. Track source identity changes between measurements as possible causes of path differences.

Normalize method-specific terminal responses, ICMP error codes, RTT samples, reply addresses, quoted probe identity and exposed ICMP extensions. Preserve MPLS label evidence and interface extensions when available. A destination-originated Time Exceeded response is not terminal completion; administrative rejection is not successful service access. Retain invalid reported RTTs diagnostically without turning them into latency or fabricated timestamps.

For IPv6, replace the client string prefix with configured IPv4/IPv6 CIDRs and explicit gateway addresses; carry canonical family-aware tuples through conntrack, demand, storage and selectors. Validate actual client IPv6 routing, router advertisements/address provisioning, return routing and firewall behavior on a dual-stack test gateway. Do not invent a delegated prefix or enable IPv6 forwarding on an unconfigured uplink. Report `IPv6 unavailable in this gateway configuration` separately from an unanswered IPv6 trace. IPv4 and IPv6 results never share a topology or cache entry.

## 6. Scheduling, budgets and cache policy

Do not probe every connection with every method. Coalesce demand by compatible gateway source context and observed destination binding. Retain recent-byte priority, a fairness reservation, bounded queues and independent traffic display.

Proposed starting policy, to be tuned on the Pi:

| Control | Initial setting/behavior |
| --- | --- |
| Ordinary measurement concurrency | Two tasks; one outstanding TTL per task initially. Increase only after matching tests. |
| Aggregate transmitted probe rate | Ten probes/second across ordinary and optional work, with at least 200 ms spacing within a task. Account separately for engine-generated resets/control packets. |
| Ordinary trace limits | TTL/hop limit 32, at most three probes per TTL, 60-second wall-clock deadline, hard packet budget of 96. A slow trace may end before covering all TTLs. |
| Comparison round | First method plus at most two alternatives; alternatives use remaining demand and budget, with 15-second separation and a ten-minute cooldown after the round. |
| Stable sparse result | Stop repetitive gap chasing. Refresh on demand/freshness policy, network change, or explicit inspection. |
| Engine fault | Per-capability circuit breaker; report permission, unsupported method/family, decoder or receiver failure distinctly. |
| Preemption | Optional work yields to new demand; already received evidence survives. Cancelled work does not advance a successful comparison round. |
| Queue/storage | Start with existing 1,024 pending bindings and 10,000 cache entries; bound event bytes and expose deferred demand. |

The rate is a global ceiling, not a per-worker multiplier. Budget MDA and alias work through the same limiter. Lower concurrency when measurements show local receiver pressure; do not infer upstream ICMP rate limiting merely from stars. No-reply patterns can inform a cautious cooldown, not a permanent declaration that a network is unmeasurable.

Publish endpoint and queued/running/unsupported state within the existing five-second UI target. There is no five-second guarantee for an externally responding hop. Method comparison is not conditional on an incomplete first route alone: explicit inspection can request it even if every TTL answered.

Separate these cache functions:

- **Binding:** gateway/source context, canonical destination IP, family, observed transport/port and measurement-policy version.
- **Measurement compatibility:** actual probe method/port, engine behavior version, source/probe-flow context. Different methods and probe flows remain separate evidence.
- **Reuse:** timestamped historical evidence that can be attached to a new session, with a new availability time and its original measurement time.
- **Selection:** latest applicable measurement, plus a separately identified richer historical result. A sparser new measurement must not silently disappear behind an old rich one; a failed refresh must not erase or rejuvenate old evidence.
- **Visibility memory:** recent completed silent/partial results prevent repeated fruitless attempts. This is independent of whether a drawable route exists.

Retain current ten-minute fresh/one-hour stale reached-evidence defaults initially. Keep partial evidence's short default reuse conservative, but allow visibility cooldowns to survive its expiry. Make freshness visible in the UI. Add source route/interface/family context to the existing network fingerprint and isolate unknown contexts. Local fingerprints cannot detect every upstream route or anycast change; freshness remains an approximation.

## 7. Versioned evidence model

Use additive v2 records. Do not attempt to express the new contract through another `complete` boolean.

| Entity | Responsibility and required data |
| --- | --- |
| Existing `flows` | Observed client tuple, timestamps and sampled activity. Carry client/source context into route demand without treating it as the probe source. |
| New `route_measurements` | Attempt ID; engine/version/policy; gateway/vantage/source context; target and probe signatures; start/end; budgets; final execution outcome and stop reason; bounded raw-output reference/hash. |
| Existing `route_observations`, v2 payload | Append-only observation batches/revisions belonging to one measurement: probe/TTL identity, transmitted-count evidence, response fields, timestamps, timeouts and engine events. Idempotent sequence numbers. |
| New `ip_evidence` | Versioned prefix/ASN, operator, PTR, location and alias claims, each with evidence source, lookup time, availability time and confidence/reason. |
| Existing `routes`, v2 projection | Immutable session availability revision referencing measurement and enrichment revisions; binding, summary, explicit unknown spans, latest result and separate historical/comparison references. |
| Existing `route_cache`, v2 namespace | Replaceable reuse/index/policy state. Never the only surviving copy of evidence used by a recording. |
| Optional topology/comparison result | MDA graph, alias associations or external measurement, with its own method, vantage, time and completion/confidence limits. Not a linear hop array. |

Separate the state axes:

- Execution: `queued`, `running`, `finished`, `cancelled`, `engine_error`, `unsupported`.
- Stop reason: destination response, hop limit, packet/time budget, explicit unreachable, loop, cancellation, local error, or unknown legacy termination.
- Endpoint probe result: `responded`, `explicit_unreachable`, `not_observed`; include the actual terminal evidence and its method. This is separate from observed client activity.
- TTL/probe observation: `waiting`, `reply`, `no_reply`, `send_error`, `not_probed`, `unknown`. `no_reply` requires evidence that the corresponding probe was sent and its wait elapsed. If the engine cannot establish that, use `unknown` and retain its raw summary.
- Topology completeness: counts/ranges and explicit uncertainty, not a binary success flag.

Store every responder independently. A TTL with multiple addresses means “multiple responders observed,” not automatically a verified ECMP branch. Preserve probe counts separately from responding TTL counts, and exclude never-probed tails from response ratios. Do not invent counts when a legacy/engine format omits them.

Enrichment carries claim-level confidence rather than one whole-route score. Separate prefix origin ASN from inferred interface operator and inferred router identity. A router alias ID remains null until supported by an explicit inference. Location is nullable and may have conflicting hypotheses; include source/version, granularity, accuracy radius and rationale.

Preserve start, send, receive, finish, persistence/availability and enrichment-availability times separately. If a timestamp is unknown, leave it unknown. An enrichment learned later cannot appear at an earlier playback cursor. Every referenced version must survive global cache eviction while the session remains retained.

Avoid duplicating all per-probe events into every session revision. Keep bounded batches and references, with compact summary projections for overview and paged detail. Account explicitly for the existing 128 KiB observation and 256 KiB cache limits. Add indexes on attempt/sequence, session/binding/availability and IP/evidence version; extend reset, clear-observations, export and retention handling to all new records.

## 8. Useful network and geographic interpretation

Implement a shared classifier for private, loopback, link-local, multicast, unspecified, CGN shared, documentation/reserved and public-address candidates in both families. Use an explicit maintained prefix policy rather than treating `IsPrivate == false` as globally routable. Preserve private/CGN hop observations, but do not perform public GeoIP/ASN inference on them.

For every responding public interface and actual remote endpoint:

1. Resolve longest-prefix/origin-AS and organization context from a versioned local dataset. Support unknown and multiple-origin results. Dataset acquisition/update failure must not block measurements.
2. Perform bounded PTR lookup as a separate evidence source. Do not replace the observed IP with a hostname and resolve it back to another address.
3. Record GeoIP as a geographic hypothesis, including database version and accuracy radius. Country-only or no location is an acceptable result.
4. Add conservative PTR location rules with evidence and confidence. Remove automatic “any three-letter token is an airport” inference.
5. Use trustworthy source-location/RTT information only to reject implausible hypotheses, with allowances for measurement quality and routing asymmetry. Do not subtract adjacent RTTs to estimate link delay or turn RTT into a precise coordinate.

Construct a partial network sequence from observed interfaces with prefix/ASN annotations and retained gaps. Collapsing consecutive equal ASNs is a presentation convenience, not proof of ownership or direct peering. Where intermediate evidence is absent, still show the destination network; do not synthesize a transit path.

Anycast location evidence must be scoped to vantage/time. A GeoIP coordinate or different remote trace alone does not prove the actual reached instance. Missing MPLS extensions do not prove the absence of MPLS; silent positions do not prove a tunnel. Treat those explanations as hypotheses unless supported.

## 9. Research capabilities without unbounded background work

Include the report's advanced capabilities as explicit later slices, with separate evidence types and budgets:

| Capability | Product use | Trigger and limit |
| --- | --- | --- |
| MDA / `tracelb` | Discover a graph of alternative per-flow paths. | User-requested or tightly bounded investigation of selected destinations. Start with 95% requested confidence; record incomplete/budget-limited results without claiming achieved confidence. |
| Repeated measurement / MTR | Compare endpoint response and RTT distributions over time. | Diagnostic sampling of selected bindings. Label intermediate nonresponse as probe-response loss, not application packet loss. |
| BGP/RIS/RouteViews context | Explain prefix origins and compare plausible network paths. | Offline snapshots or bounded optional lookup with collector/vantage/time recorded. Never fill missing measured TTLs with collector AS paths. |
| RIPE Atlas | Compare other vantage points and investigate possible anycast or ISP-specific behavior. | Optional configured integration with explicit measurement creation, quotas and provenance. Remote observations never become the gateway's measured path. |
| Alias resolution | Group interfaces into inferred routers when supported. | Selected candidate interfaces only; independent evidence/confidence. Avoid broad active discovery in the default workload. |
| IPmap or comparable location evidence | Add another geographic hypothesis. | Optional bounded enrichment; preserve source scores without converting them into unsupported probability percentages. |

Scamper provides both single-path trace and MDA measurement primitives, as well as alias techniques. The distinction should remain visible in the data model and product. [CAIDA Scamper overview](https://www.caida.org/catalog/software/scamper/)

Deliver local network context before these integrations. The baseline product must remain useful offline and without external accounts. DNS A/AAAA/HTTPS/SVCB evidence can be retained when observed, but should never cause speculative tracing of every advertised address or replace the actual endpoint binding. Process/browser identity remains unavailable unless a separate endpoint source supplies it.

## 10. Shared UI and replay rewrite

Make a non-geographic topology view the primary route explanation. It shows the gateway measurement origin, responding interface IPs, network annotations, unknown TTL ranges and separately observed destination. Geography becomes a secondary view of location hypotheses; absent coordinates must not hide useful path evidence.

Example: **“Client traffic observed to 203.0.113.24:443 over TCP. Gateway probe received a destination response at TTL 13. Three of 13 attempted TTL positions responded; TTLs 3–12 did not respond. Two interface locations are approximate.”** Fixture addresses in examples are not targets for live probing.

Expose actual method, family, source context, measurement age, cache age, latest attempt outcome and alternate measurements. Expand a TTL to inspect individual replies. Never assign a coordinate to a silent hop, place unknown geography at `(0,0)`, label an interface as a confirmed physical router, or draw unqualified physical links, even between consecutive responding TTLs. Keep endpoint-only connections visually distinct from a measured TTL sequence. MDA branches require a graph view rather than flattening into one path.

Incoming/outgoing animation is a visualization of recorded activity associated with the gateway approximation. Explicitly state that the reverse path is unmeasured; do not say incoming bytes are known to follow the displayed route.

Concrete consumer work:

- Extend `packages/session-state/src/data/types.ts`, `routeEvidence.ts` and exports with discriminated v2 types, one legacy adapter, shared counters/labels and topology projection.
- Preserve `routeForFlowAt`'s exact session/IP/protocol/port selection and latest-before-validity behavior; extend it for source context where needed. A newer invalidation must never resurrect older evidence.
- Update `pocketbaseClient.ts`, backend `session_routes.go`, and session-store paging/reconciliation for versioned references and independent enrichment availability.
- Update `dashboard/src/map/mapRoutes.ts` and `MapRouteDetails.tsx`, plus debug TrafficInspector and TrafficUtilities, to use the same interpretations.
- Fix Proxy Lab `NodeInspector.tsx` IP-only lookup and `projectRecordedEvents.ts` use of completion time instead of availability time.
- Replace IP+port/insertion-order selection in `debug-dashboard/src/model/sessionModel.ts`, including remaining recorded-video projections, with shared binding/time semantics.

These changes address specific consumers that would otherwise undermine a correct backend rewrite.

## 11. Implementation sequence and acceptance gates

| Slice | Concrete work | Gate before progressing |
| --- | --- | --- |
| 0. Baseline | Extend diagnostic/harness; inspect affected Pi/uplink; capture versioned fixtures and counters. | Identify where evidence is lost, or establish a measured visibility limit with uncertainty. Lack of Pi access does not prevent schema/fixture work, but field diagnosis remains open. |
| 1. Contract and compatibility | Add v2 types, state axes, migrations, immutable evidence/reference rules and legacy adapter. Record a new architecture decision for this contract. | Old recordings still play; new states and time semantics pass deterministic tests. |
| 2. Engine replacement | Pin/build Scamper for ARMv7/ARM64; implement whole-task adapter, structured output, progressive capability, cancellation and protocol-aware replies. | Shipped executables pass isolated IPv4/IPv6, NAT, matching and cancellation tests. Every captured matching reply is accounted for in the deterministic fixtures. |
| 3. Orchestration and reuse | Replace fast/repair split, budgets, no-response policy, cache compatibility and latest-versus-historical selection. | Burst/fairness/rate limits, engine restart and session/reset tests pass; no recursive probe demand. |
| 4. Network evidence | Add shared address classifier, ASN/prefix/PTR enrichment, location hypotheses and versioned provenance. | Private/CGN addresses are never geolocated; missing datasets do not block routes; later enrichment does not leak backward in replay. |
| 5. Product cutover | Shared selectors/explanations; topology view; map and both dashboard consumers; diagnostic status. | Same fixture yields the same meaning across all views; zero located hops still produces useful endpoint/topology information. |
| 6. Field qualification and default switch | Sequential old/new comparisons under matched budgets; cold/warm Pi workloads; controlled rollout and rollback exercise. | Recorded packet, software, UI and resource metrics meet the agreed gates; upstream silence remains explicitly represented. |
| 7. Advanced evidence | MDA graph, repeated diagnostics, optional BGP/Atlas/IPmap and alias adapters. | Each output retains its own vantage, time, confidence and budget limits; none changes the meaning of baseline observations. |

Slices 0–6 constitute the production rewrite. Slice 7 completes the broader research tooling and can ship incrementally without holding up a useful baseline. Within that sequence, data contracts precede consumers; the engine capability qualification precedes promises about progressive publication.

## 12. Verification, metrics and rollout

Preserve current routing race/cache/reset tests, route-history pagination tests, shared temporal-selection tests and map gap tests. Replace implementation-specific four-hop tests with whole-measurement invariants. Add fixture cases for:

- All-silent route; destination after a silent middle; responding prefix with no destination response; explicit unreachable; cancelled task; never-sent tail; unknown probe counts.
- TCP SYN-ACK/RST, UDP port-unreachable, ICMP echo, ICMPv6 terminal/error replies and destination Time Exceeded.
- Local INPUT drop versus upstream silence; delayed/duplicate/out-of-order replies; NAT translation; wrong quoted tuple; engine restart and identifier reuse.
- Multiple responders at one TTL; stable-flow ECMP; different flows across attempts; branches that must never be stitched into one path.
- Malformed/truncated output, wrapped RTT, packet/output limits, decoder error after valid progress, ICMP extensions and IPv6 extension headers.
- Private/CGN addresses, multiple-origin ASN, absent/conflicting geography, anycast-scoped hypotheses and versioned enrichment.
- Same IP across transports/ports; cache evidence older than session availability; no future enrichment; session close/reset/network changes; legacy records with insufficient semantics.

Measure distinct denominators: eligible observed bindings, attempted measurements, confirmed sent probes, completed TTL waits, responding TTL positions, raw replies, matched replies, endpoint responses, enriched interfaces and located interfaces. Break down by engine/version, method, family and source network. Engine failure rate must exclude ordinary no-response results; geography coverage must not stand in for measurement correctness. Report unavailable counters as unknown.

Field acceptance should include at least three repeated cold/warm workload runs using the services in the existing Pi guide, plus a mixed-destination burst. Capture p50/p95/max observation-to-UI latency, time to first reply, endpoint response, queue age, attempt counts, CPU/RSS, persistence latency, packet rate and history growth. Require endpoint/state display within five seconds on the healthy reference workload, adherence to configured budgets and no material regression in client forwarding. Set numerical resource limits from the measured baseline before switching defaults; no unmeasured Pi performance guarantee is implied here.

Run `pnpm test`, `pnpm lint`, `pnpm build`, `go test ./...`, the routing race suite, Linux namespace tests with the shipped engine, and ARMv7/ARM64 builds during implementation. Browser acceptance covers both dashboards and recorded playback. This planning change itself does not require rerunning application tests.

Roll out with `ROUTE_ENGINE=legacy|v2|off` and an isolated v2 cache namespace. Read both schemas; write v2 only from the v2 engine. Compare engines sequentially or on a small explicitly budgeted sample so shadow work does not create its own ICMP suppression. Use additive migrations, a pre-deployment backup and version-compatible readers. Switching back stops v2 probes and restores the old engine without deleting recordings; verify rollback against a migrated database.

After qualification, make v2 default and remove the old fast/coverage implementations, obsolete parser/state branches and reachable legacy hostname-traceroute paths. Keep the independent diagnostic executable and explicit historical read adapters. Update `CONTEXT.md`, README, implementation/validation guides, Docker/runtime configuration and the documentation index to describe measured behavior.

The release is successful when it preserves all evidence the software receives, identifies its own failures, provides useful endpoint/network context despite silence, and makes unsupported inferences impossible in the ordinary UI. Recovering responses suppressed by the upstream network is not a capability this rewrite can promise.
