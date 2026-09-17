# Implementation plan: a few useful route approximations

Status: implementation and local validation completed on 17 September 2026; remaining unchecked release/field qualifications are listed explicitly. See [validation results and limitations](docs/validation/live-route-discovery.md).

Qualification adjustment: the pinned Scamper build failed UDP Paris reply correlation in the IPv6 namespace fixture. Automatic IPv6 UDP destinations use the verified ICMP Paris approximation with one allowed method. No futile UDPv6 comparison is scheduled. ARMv7 cross-builds pass; its executable qualification on the deployed gateway remains outstanding.

## Objective and priority

**Produce a small number of useful visual approximations of the route to observed destinations. Stop spending probe traffic, CPU, storage and UI attention on repeated observations that add nothing.**

The motivating failure is one lightly used session producing **5,200+ route records, most essentially useless**. Ten useful paths are preferable to thousands of empty, duplicated or repeatedly incomplete records. A hundred records is a ceiling to defend, not a collection target. If the network reveals no usable path, store a compact explanation and stop.

This checklist supersedes the execution order, default budgets and persistence design in [the earlier rewrite proposal](docs/proposals/traceroute-rewrite.md). [The research report](deep-research-traceroute.md) supplies the measurement principles. [ADR 0001](docs/adr/0001-metadata-gateway-not-transparent-tls-proxy.md) remains in force: client forwarding is independent of probes, and the result is a gateway-measured approximation.

Implement the waste controls first. A new engine, richer schema or more diagnostic data does not count as success if it recreates the record explosion elsewhere.

## 1. Define what deserves collection and storage

| Result | Product treatment | Persistent treatment |
| --- | --- | --- |
| No responding interfaces | Endpoint remains visible; “Path not observable with these probes.” | One bounded outcome summary; zero route snapshots. |
| Destination response only | Useful endpoint-response fact, but no discovered intermediate path. | Outcome/endpoint summary; zero route snapshots. |
| Only the same local/access prefix, destination not reached | Show a compact access-prefix explanation; remote path remains unknown. | Reuse a bounded access-context summary; do not keep duplicating it as destination routes. |
| At least one public intermediate responder beyond an established shared access prefix | Useful partial route, even without geography or destination response. | Retain one path snapshot with its measured TTLs and explicit unknown spans. |
| Destination response plus at least one intermediate responder | Useful sparse approximation, even with unanswered intermediate TTLs. | Retain one path snapshot; gaps remain explicit. |
| Same path with additional timeout rows, another timestamp or small RTT changes | No new route information. | Update bounded summary statistics; zero new route snapshots. |
| Additional responding segment, newly reached destination, or changed interface sequence | Potentially useful new evidence. | Publish a new snapshot if materially different and within the session budget. |
| Coordinates/ASN added to an existing interface | Improve its explanation/rendering. | Version the changed enrichment once; do not duplicate the whole route. |

- [x] Implement a pure `classifyRouteEvidence` policy with fixture tests for every row above, returning `useful_path`, `access_only`, `endpoint_only`, `no_path`, or `indeterminate` and a reason.
- [x] Define an access prefix conservatively: matching leading responding TTL/address positions in at least three independent destination measurements in the same network context. Do not guess it from ASN, geography or address ownership alone.
- [x] Before an access prefix is established, permit a public intermediate reply as provisional useful evidence; subsequent matching prefixes add no new path evidence. Historical records need not be rewritten to reflect later classification.
- [x] Keep supporting measurement IDs and times for access-context summaries. Display shared context as context, never splice it into an unmeasured destination's route.
- [x] Define a material path fingerprint from canonical target binding, source/network context, actual method/port, TTL-indexed responder sets, terminal evidence and meaningful unknown spans. Exclude attempt IDs, wall-clock timestamps, raw RTT values, queue state and timeout-only tail growth.
- [x] Preserve measurement identity separately from that fingerprint. Identical topology does not make two attempts the same observation.
- [x] Define changed paths as observed alternatives or changes; if the synthetic source-flow identity changed, do not assert that the network itself changed.

Acceptance:

- [x] Replaying 1,000 identical all-silent or access-only results creates **zero per-destination route snapshots after classification**, with bounded summaries rather than 1,000 replacement diagnostic rows.
- [x] A destination replying after a long silent middle produces a useful approximation when an intermediate interface also replied.
- [x] A useful unlocated route is retained and visible in a topology strip; lack of GeoIP never makes it useless.

## 2. Set hard automatic-work budgets

These are initial implementation defaults, intentionally smaller than the existing system. Expose them in configuration and diagnostics. Changing them must be deliberate; no hidden queue, retry or alternate engine may bypass them.

| Limit | Default |
| --- | --- |
| Targets admitted for automatic probing per session | 20 distinct destination bindings, cumulative; eviction does not replenish this allowance |
| Targets considered for admission at once | Top 10 by recent byte volume, using a 30-second window |
| Automatic qualification | At least 1 MiB transferred, or positive byte deltas in at least three samples spanning ten seconds |
| Attempts per admitted target | One primary attempt plus at most one alternate if the primary adds insufficient useful information |
| Automatic attempts per session | 40, including cancelled and failed starts once admitted to the engine |
| Automatic attempts per gateway/network/family | 40 per rolling hour, persisted across process restart and session changes |
| Concurrent automatic traces | One |
| Probe rate | Five measurement probes/second globally; record engine-generated control traffic separately |
| One trace | Maximum 32 TTLs, two probes per TTL, 64 transmitted probes, 45-second wall deadline |
| Persisted path snapshots | Maximum 100 new v2 `routes` snapshots per session, including useful cached bindings and material revisions |
| Snapshots per attempt | At most two: first useful result and materially different final result; no per-hop history |
| Detailed unsuccessful attempt retention | One compact current outcome per admitted binding; no append-only automatic failure/progress log |
| Negative result suppression | At least 30 minutes per network/binding/method; persists across sessions and restart |
| Network visibility suppression | After five distinct targets each finish the allowed comparison without useful new path evidence, pause automatic discovery for that network/family for 30 minutes |

- [x] Count allowances transactionally and restore them on restart; neither process restarts nor demand eviction may reset spent budgets.
- [x] Admit new work only when attempt, packet and persistence budgets can support its outcome. Reserve path capacity for an active attempt's final useful result.
- [x] Maintain the rolling-hour limit independently of session counters. Do not clear either merely because a route cache entry expires.
- [x] After visibility suppression expires, permit one bounded trial on renewed qualified demand. Reopen discovery only if it adds useful evidence; otherwise suppress again.
- [x] Treat a shared sparse prefix as no information gain for this stopping rule. Label the result “no additional path visibility under tested methods,” not “ISP blocks traceroute.”
- [x] Once a target has a useful result, stop automatic probing of that binding for the rest of the session. Freshness expiry may change its label, but must not restart a repair/refresh loop. A network-context change may make it eligible again only within the remaining session/hour budgets; explicit manual requests use their own allowance.
- [x] Cancel queued work when its demand disappears; do not trace every hostname, IP, DNS answer or flow just because it exists.
- [x] Select fairly among qualifying targets, without using fairness to grant unconditional probes to every background connection.
- [x] Allow an explicit “Measure this destination” action to prioritize a selected observed binding even below the traffic threshold. Give manual work a separate small allowance of ten attempts per session; retain global rate, concurrency, storage and capability limits.
- [x] Require explicit user action to extend a session's finite collection budget. A long recording may legitimately stop collecting new routes while traffic observation continues.
- [x] Separate engine capability failures from negative visibility results. A missing binary or denied socket should open a capability circuit breaker, not consume repeated comparisons for every destination.

Acceptance:

- [x] A 1,000-destination burst cannot cause more than 20 automatically admitted targets or 40 automatic attempts in one session.
- [x] Repeated fully silent comparisons stop after five targets and at most ten attempts in the controlled fixture; continuing identical traffic does not restart probing during suppression.
- [x] A usable route stops its automatic comparison round. Missing individual hops do not create an obligation to repair it indefinitely.
- [x] Restart, session switch, cache expiry and queue eviction cannot bypass negative suppression or rolling-hour limits.

## 3. Diagnose and stop the current record amplification

Files: `pocketbase/routing/coordinator.go`, `storage.go`, `types.go`, `probe.go`, `coverage.go`; `pocketbase/cmd/route-diagnose/`; routing tests.

Confirmed from code: the coordinator publishes queued/probing transitions and progressive updates, while `repository.publish` creates a new `routes` record each time. The same retained path can therefore be copied into repeated revisions. Retry and coverage decisions continue pursuing incomplete routes. This explains a mechanism for amplification; the exact contribution to the reported 5,200+ rows still needs measurement.

- [x] Add a read-only session audit reporting route rows, distinct target bindings, attempts, material fingerprints, zero-reply rows, access-only rows, repeated cached copies and actual useful paths.
- [x] Audit `route_observations`, cache payloads and database bytes as well as `routes`, so the rewrite cannot hide the same volume in another collection.
- [ ] Run the audit against an export/copy of the affected recording and save aggregate results in `docs/validation/live-route-discovery.md` or a linked validation artifact.
- [x] Separate `publishProgress`, `recordOutcome` and `publishUsefulPath`; route all path writes through one admission/deduplication gate.
- [x] Stop creating route rows for queued/running/cancelled/failed/no-reply status alone.
- [x] Coalesce live progress to at most one update per second per running attempt; do not persist progress ticks.
- [x] Stop copying unchanged best-path data into a new route revision when a refresh starts, fails, times out or reproduces the same path.
- [x] Replace “coverage below 100%” as an automatic retry condition with explicit expected information gain and the budgets in section 2.
- [x] Apply these controls to the existing engines before the Scamper cutover, so the storage/probe reduction can ship independently.

Acceptance:

- [x] A fixture of 5,200 queued/progress/retry publications with unchanged displayed evidence produces at most the first useful snapshot and one materially improved final snapshot per attempt, with identical completed paths deduplicated across attempts.
- [x] The same fixture with no useful evidence produces zero `routes` snapshots.
- [x] The waste-control change works before any improvement in real-world ICMP response rates.

## 4. Store useful paths and bounded operational state

Files: `pocketbase/routing/storage.go`, new routing policy/persistence files, new migrations, `pocketbase/session_routes.go`, session/reset/export handlers.

| Storage | Responsibility | Growth rule |
| --- | --- | --- |
| `routes`, v2 | Immutable useful path snapshots, with measurement/source/method/availability metadata | At most 100 per session; no status-only rows |
| `route_observations`, v2 | Compact evidence retained for accepted path snapshots | At most one bounded evidence bundle per snapshot; no endless progressive copies |
| New `route_outcomes` | Last attempt classification, reason, counters and last-attempt time for an admitted session binding | Upsert one row per binding; initial automatic/manual allowances bound new rows |
| `route_cache`, v2 | Reusable useful evidence, negative suppression and last-attempt summary | Bounded entry count and bytes; cache expiry does not erase budget/suppression state |
| New `route_budget_state` | Session spending, rolling-hour spending and network visibility cooldown | Bounded counters/timestamps, persisted atomically; no per-probe ledger |
| New `route_evidence_updates` | Rare confirmation, invalidation or changed enrichment availability for retained paths | Coalesced events; maximum 100 per session; separate from path geometry |
| Network context epochs | A network-change event can invalidate many bindings together | Store actual changes, not one duplicate route per binding |
| Live progress | Queue/running state and transient probe progress | Memory/realtime only; recover current state through a status endpoint |

- [x] Add schema versions and a new migration; leave applied migrations unchanged.
- [x] Enforce snapshot/outcome/event byte limits, e.g. 64 KiB per evidence bundle, 4 KiB per outcome and 16 KiB per update event. Reserve the existing larger limits only for explicit legacy compatibility.
- [x] Add a configurable 16 MiB session budget for newly stored v2 measurement evidence; stop collection before exceeding either row or byte budgets. Count serialized snapshots, bundles, outcomes, enrichment, updates and references; report physical database growth separately, including indexes. Minimal budget counters and authoritative network-change control events remain outside this payload allowance so reaching it cannot break correctness.
- [x] Use atomic idempotency keys for accepted snapshots/publications so persistence retries cannot duplicate records or double-charge allowances.
- [x] Preserve exact session/IP/family/protocol/port/source-context compatibility; share measurements across compatible flows instead of making one route per connection.
- [x] Do not share measured paths across different IPs, ports or protocols just because hostname, provider, ASN or location matches.
- [x] Store only observed TTLs and compact unknown ranges; do not create one database record per silent hop.
- [x] Retain all responder addresses within the accepted bundle; do not reduce multipath observations to a falsely certain single address chain.
- [x] Bound per-attempt raw output in memory and discard it after normalization. Persist raw headers/output only during an explicit diagnostic with a size limit and automatic expiry.
- [x] Preserve previous useful evidence after a failed refresh, with its original age and “historical/cached” label. The outcome summary exposes the failed/latest attempt without another copy of the path.
- [x] If the same path is confirmed later, coalesce a compact confirmation event only when needed to extend freshness; do not append geometry again.
- [x] On event-budget exhaustion, stop refresh/enrichment work and let evidence age. Never silently mutate historical freshness or suppress a necessary invalidation to satisfy a quota.
- [x] Keep network invalidations authoritative even after evidence collection stops. These control events are not useful paths and are not multiplied per destination.
- [x] Update retention, session deletion, clear-observations and export for new records. Useful session evidence must survive global cache eviction.
- [x] Keep failed/progress state out of historical path replay. Mutable outcome summaries must be presented as current/session summaries, never as facts known at an earlier playback cursor.

Acceptance:

- [x] Row/byte budgets are enforced in the persistence layer, including concurrent callbacks and crash/retry cases.
- [x] The 5,200-row reproduction does not relocate into 5,200 attempts, observations, outcome revisions or enrichment events.
- [x] Identical path confirmations reuse geometry; playback before confirmation sees the original freshness.
- [x] Exhausting a budget leaves existing history readable and client forwarding unaffected.

## 5. Measure the right target with one controlled engine

Files: `pocketbase/routing/probe.go`, `coverage.go`, `diagnostic.go`, `types.go`, `Dockerfile`, `docker-compose.yml`, `scripts/test-route-coverage-netns.sh`.

- [x] Keep observed conntrack destinations as targets. Carry source/client attribution context, but record the gateway probe tuple separately; do not imitate a live client tuple.
- [ ] Pin and qualify Scamper plus its structured decoder on the actual ARMv7/ARM64 runtime.
- [x] Use one logical trace task across the TTL range. Remove the four-TTL subprocess assembly and the separate high-concurrency fast-probe loop.
- [x] Implement one bounded adapter that owns execution, matching result identity, cancellation, structured decoding and final classification.
- [x] Prefer a whole-task subprocess adapter for the initial one-at-a-time workload; add a supervised control socket only if required for verified progress/cancellation behavior. Do not make daemon infrastructure a prerequisite for reducing waste.
- [x] Use TCP SYN to the observed port for TCP targets and UDP Paris to the observed port for UDP targets; use ICMP Paris as the single automatic alternate when the primary is insufficient.
- [x] Keep other methods available only for explicit diagnostics. A UDP/443 flow does not prove QUIC, and a silent UDP probe does not prove endpoint failure.
- [ ] Verify stable flow-selection fields, unique reply correlation and late-reply isolation in namespace tests.
- [x] Distinguish terminal protocol replies, destination Time Exceeded, explicit unreachable, no response, local send failure and cancellation.
- [x] Preserve validated progress on cancellation. Publish at most the useful milestones allowed by section 2; engine streaming must not reintroduce per-reply persistence.
- [x] Decode ICMP/MPLS extensions if present in the selected engine format; preserve them as evidence without inferring hidden physical topology.
- [x] Extend the diagnostic to compare the actual old/new engines with outgoing probes and matching incoming ICMP/TCP metadata. Report capture drops and match failures.
- [ ] Determine whether the affected uplink loses evidence in transmission, reception, matching, parsing, persistence or display; retain uncertainty if no responses arrive.

Acceptance:

- [ ] Controlled fixtures account for every captured matching response and correctly classify unsent/cancelled TTLs.
- [x] All engine paths obey the same packet, attempt, concurrency and output budgets.
- [x] A slower, richer trace is acceptable when it produces useful evidence; showing observed traffic and measurement status remains independent of trace completion.

## 6. Enrich only evidence worth showing

Files: new shared IP-evidence module, `pocketbase/routing/storage.go`, `pocketbase/observer/destination.go`, `scope.go`, shared frontend types.

- [x] Add one shared address classifier covering private, shared/CGN, loopback, link-local, multicast, unspecified and other special-purpose prefixes in both families.
- [x] Preserve private/CGN responders as unlocated topology evidence; never send them through public GeoIP inference.
- [x] Enrich retained responding interface IPs and selected observed endpoints; do not run lookups for timeout placeholders or every discarded diagnostic result.
- [x] Deduplicate lookups by IP and dataset version; cache positive and negative results with bounded memory/storage.
- [x] Add prefix/origin-AS/organization context from a versioned local source; keep origin ASN separate from inferred router operator.
- [x] Keep PTR and GeoIP as separate evidence, including source, lookup time, confidence and accuracy radius where available.
- [x] Remove airport-token guessing and hostname → re-resolution from legacy route code.
- [x] Version materially changed enrichment at its availability time, with batching through the event budget. Do not rewrite route geometry for a label update.
- [x] Bound enrichment output within the session byte budget; missing data must not block path display.
- [x] Make client observation scope CIDR-based and family-aware. Validate IPv6 end-to-end only on a configured dual-stack gateway; expose unsupported gateway configuration rather than launching doomed IPv6 work.

Acceptance:

- [x] One hundred references to the same interface reuse its evidence rather than issue one hundred lookups.
- [x] Zero located interfaces still yields a useful logical route when responding interfaces exist.
- [x] Later geography never appears earlier in recorded playback.

## 7. Render the best available approximation

Files: `packages/session-state/src/data/{types,routeEvidence,pocketbaseClient}.ts`, session-store selectors, `dashboard/src/map/{mapRoutes,MapRouteDetails}.tsx/ts`, both debug inspectors and recorded projections.

The primary experience remains a visual approximation to the destination. A compact topology strip supports the map when geographic evidence is sparse. The user should not have to inspect thousands of failed measurements to discover whether anything useful was learned.

- [x] Show one selected approximation per compatible destination binding, with at most one best historical alternative exposed on demand.
- [x] Draw located observed interfaces in measured TTL order. Mark every geographic connection as an approximation; distinguish unknown spans visually.
- [x] Show unlocated responding interfaces in the topology strip without inventing coordinates.
- [x] When the destination is known but the path is not, optionally draw a subdued/dashed endpoint connection labeled “Destination known; intermediate route unknown.” Never count that line as a discovered useful route.
- [x] Collapse repeated silent TTLs into an “Unobserved segment” with its measured TTL range. Keep the never-probed tail distinct.
- [x] Keep different methods/attempts separate; never join their strongest individual hops into a fabricated path.
- [x] For multiple responders at one TTL, show ambiguity rather than a confirmed physical router/branch graph.
- [x] Show a concise state: useful partial path, destination reached with gaps, historical path, not selected for measurement, budget reached, no additional visibility, or engine unavailable.
- [x] Show route age, actual method and endpoint binding in details; keep per-probe diagnostics behind an explicit diagnostic view.
- [x] Use “responding TTL positions,” “probe replies” and “located interfaces” as distinct counts. Ordinary unanswered TTLs are not software errors.
- [x] Associate traffic animation with the approximation; label the reverse path as unmeasured. Never derive link latency from differences between adjacent RTTs.
- [x] Preserve `routeForFlowAt` exact binding and availability selection; extend it to separate confirmation/enrichment/network-epoch events without resurrecting invalidated routes.
- [x] Replace IP-only selection in Proxy Lab `NodeInspector.tsx`, completion-time event dating in `projectRecordedEvents.ts`, and IP+port/insertion-order selection in `debug-dashboard/src/model/sessionModel.ts`.
- [x] Update backend route paging and shared runtime loading for sparse snapshots and separate status; a missing `routes` row no longer means missing observed traffic.
- [x] Recover live status via bounded reconciliation, without writing queued rows merely to make them available to the browser.
- [x] Define useful-route counts from accepted snapshots/unique bindings, not from queued work, endpoint-only fallback lines or total database records.

Acceptance:

- [x] Fixtures show: a fully located approximation, sparse reached route, unlocated useful route, shared access-only context and endpoint-only fallback.
- [x] Both dashboards select the same evidence for the same flow/time.
- [ ] Before/after screenshots demonstrate a small set of understandable paths and explanations rather than thousands of no-reply items.
- [ ] Observed traffic and meaningful status appear within five seconds on the healthy reference workload; useful remote-hop response time is measured, not promised.

## 8. Preserve recordings and migrate safely

- [x] Add a legacy read adapter for existing `missing`/`no_reply`/`complete` records without inventing unavailable probe facts.
- [x] Coalesce old redundant records in the read projection where safe, while preserving the original persisted recording and true availability/invalidation transitions.
- [x] Do not automatically delete the user's 5,200-row session. Provide a dry-run audit/optional compaction command reporting exact retained/removed rows and bytes, with backup and explicit destructive execution.
- [x] Namespace new caches/policies so old retry metadata cannot re-enable repeated work.
- [x] Add `ROUTE_ENGINE=legacy|v2|off` for rollout; both active engines must pass through the new admission and persistence controls.
- [x] Compare engines sequentially on a bounded sample; avoid doubling background probes during rollout.
- [ ] Verify a rollback using an additive-migrated database without deleting v2 evidence or breaking old recording playback.
- [x] After field acceptance, remove obsolete fast/coverage publication paths and executable legacy hostname-traceroute call sites; keep necessary historical adapters and the independent diagnostic.
- [x] Update `CONTEXT.md`, README, implementation/validation guides and configuration documentation to reflect selective collection and the new meaning of `routes`.

## 9. Prove the rewrite reduces work and preserves value

Measure the before/after result on the same captured demand stream and controlled probe fixtures. Supplement that with matched real Pi sessions; Internet route responsiveness can change between runs.

| Metric | Acceptance |
| --- | --- |
| New v2 path snapshots per session | At most 100; normally much fewer |
| Snapshots for fully silent results | Zero |
| Duplicate/status-only route snapshots | Zero |
| Automatic attempts | At most 40 per session and per configured rolling-hour scope |
| Automatic work on proven no-gain fixture | Stops after five compared targets; cooldown persists |
| Useful accepted fixture evidence | Preserved within declared budgets; no silent loss below limits |
| Total v2 route evidence | At most 16 MiB/session by default; no relocated append-only explosion |
| Same-session recorded history | Time-correct across later enrichment, confirmation, expiry and network changes |
| Forwarding/traffic observation | Continues when route collection is paused, exhausted, unsupported or disabled |

- [x] Add `useful_paths`, `unique_useful_bindings`, `attempts`, `no_gain_attempts`, `suppressed_attempts`, `duplicate_publications_avoided`, `route_rows_written`, `evidence_bytes_written` and `budget_remaining` metrics.
- [x] Report useful paths per attempted measurement and per stored KiB, plus recent-byte coverage by useful approximations. Do not optimize total collected rows.
- [x] Explain why targets were skipped: low activity, reused evidence, negative cache, network visibility pause or exhausted budget.
- [x] Add deterministic tests for the 5,200-publication reproduction, all-silent stopping, shared-prefix reuse, record deduplication, budget atomicity and restart persistence.
- [x] Retain and adapt routing race/reset/cache tests, route-history pagination, exact protocol/port matching, no-future-evidence and map gap tests.
- [ ] Run namespace tests for actual shipped executables: IPv4/IPv6, NAT, filtered ICMP, terminal TCP/UDP responses, malformed output, cancellation and late replies.
- [x] Run `pnpm test`, `pnpm lint`, `pnpm build`, `go test ./...`, `go test -race ./routing`, and ARMv7/ARM64 builds.
- [ ] Repeat the minimal-activity workload and the existing SVT/YouTube/Spotify workload on the Pi with cold and warm caches. Record duration, build, configuration, targets, attempts, useful paths, total rows/bytes, packet rate, CPU/RSS and browser latency.
- [ ] On a matched reproduction of the old 5,200-row workload, require at least a 98% reduction in new route snapshot count, with no duplicate/status-only rows and no loss of useful fixture paths within the declared budgets. The hard 100-row ceiling remains independently enforced.
- [x] Confirm the all-silent case passes by stopping and explaining the limit, not by manufacturing ten “useful” routes.
- [x] Complete browser verification for both dashboards and recorded replay before default cutover.

## Delivery order

| Milestone | Checklist scope | Shippable result |
| --- | --- | --- |
| A. Stop waste | Sections 1–3 and minimum storage/status changes from 4/7 | Existing engines stop repeated fruitless work and duplicate route publication. |
| B. Preserve a few good paths | Remaining sections 4 and 7, compatibility from 8 | Useful snapshots, compact outcomes, reliable map/topology presentation and playback. |
| C. Improve measurements | Sections 5–6 | Qualified Scamper traces and better interpretation of retained evidence. |
| D. Validate and cut over | Sections 8–9 | Measured reduction in work/storage, useful visual results and safe rollout. |

- [x] Complete milestone A before investing in extra measurement modes or a broader topology research system.
- [ ] Do not mark the rewrite complete until the row/byte/work limits and visual acceptance cases are demonstrated together.

## Deferred from this rewrite

- [ ] Reconsider MDA, alias resolution, RIPE Atlas, external BGP comparisons and multi-source geolocation only after the useful-path yield and storage targets are met. None runs automatically in this release.
- [ ] Reconsider continuous route-change monitoring separately; the default product deliberately favors a finite set of useful approximations over exhaustive session-long measurement.

The end result is a small, legible set of route approximations where observation permits them, and a clear, inexpensive endpoint-only explanation where it does not.
