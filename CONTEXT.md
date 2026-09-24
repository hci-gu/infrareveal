# InfraReveal Context

InfraReveal is a consent-based network metadata observability gateway.

## Domain Terms

- Gateway: the Raspberry Pi or small computer running the Wi-Fi access point, DHCP, DNS, NAT, observers, PocketBase, and dashboard.
- Session: one observation period. An active session is live and advances from the server clock; a closed session is a recorded timeline with a fixed end. Ephemeral sessions retain a rolling window and can run continuously.
- Session runtime: the shared frontend module that loads, reconciles, indexes, caches, and controls playback for either kind of session.
- Client: a device connected to the InfraReveal Wi-Fi network.
- Flow: a sampled remote network connection initiated by a client to a public destination IP and port. Gateway-generated probes and local infrastructure protocols are excluded.
- Observation: raw metadata collected by the gateway, such as a DNS query or conntrack flow sample.
- Attribution: a derived conclusion that links a flow to a candidate hostname or destination context.
- Confidence: the strength of an attribution. Initial milestones collect observations only; later milestones add high, medium, low, and hidden confidence labels.
- Destination: the remote IP, port, protocol, and later provider or ASN context for a flow.
- Route: an approximate gateway-to-destination traceroute result. It is not the exact client application path.
- Lab mode: optional policy controls that intentionally change client network behavior to improve observability in a controlled experiment.

## Current Architecture Direction

The gateway forwards web traffic normally through NAT. It does not route HTTPS by SNI, decrypt HTTPS, or require client trust certificates.

The backend stores raw observations separately from future derived conclusions. Milestone 1 and 2 observations are:

- `flows`: sampled conntrack flow metadata.
- `dns_queries`: dnsmasq query and answer metadata.

Milestone 3 derived conclusions are:

- `flow_attributions`: candidate hostname, source signal, confidence, and explanation for a flow.
- `activity_episodes`: stable registered-domain groups per client and session, with explicit cross-domain aliases.
- `flow_associations`: separate derived links from flows to activity episodes, including relationship, confidence, score, and explanation.

Milestone 5 destination context is:

- `destinations`: reverse DNS, provider label, and coarse GeoIP context keyed by observed destination IP.
- `routes`: immutable session revisions of gateway-to-destination evidence, bound by IP, protocol, port, and availability time. A reached destination may still have unanswered hops.
- `route_observations`: bounded evidence bundles for accepted useful snapshots only.
- `route_cache`: bounded network-scoped useful evidence, retaining its original measurement age.
- `route_outcomes`: one compact current summary per admitted session binding; not historical playback evidence.
- `route_budget_state`: persisted session/hour spending, negative suppression and network visibility/capability pauses.
- `route_evidence_updates`: bounded confirmation/enrichment events and authoritative network invalidations, applied at their availability time.

The `pocketbase/routing` module consumes committed flow counters, prioritizes recent byte volume, and owns finite admission, one paced probe, cache reuse and useful-path publication. Defaults are 20 automatic targets, 40 attempts and at most 100 useful snapshots per session. Silent/status-only results never create routes. Once useful evidence is retained, automatic work stops for that binding; five unsuccessful two-method comparisons pause discovery for 30 minutes. Destination enrichment cannot block discovery. Frontends share `routeForFlowAt` to select evidence known at the playback cursor; route discovery never intercepts client traffic.

Attribution work consumes observations and writes separate derived records instead of overwriting raw observations.
Domain grouping preserves endpoint identity. Every high- or medium-confidence hostname groups by its registered domain; `pocketbase/observer/domain_groups.json` maps explicit alias domains to canonical groups. Subdomains follow their registered domain. Timing, shared providers, CNAME chains, and idle gaps do not establish or split groups. Traffic without usable hostname evidence remains independent. See `docs/implementation-guides/domain-grouping.md`.

Both dashboard applications consume the same `@infrareveal/session-state` session runtime. Dashboard-specific UI and Remotion projections remain outside that shared module.

## Continuous lab demo

`DEMO_MODE=true` designates one persistent ephemeral session. Its configurable
retention (`DEMO_RETENTION_MINUTES`, default 30) is published in the manifest and
used by both dashboards. `/demo` is the unattended live display. Recorded sessions
remain bounded recordings; existing ephemeral sessions default to five minutes.
Ephemeral route admission renews hourly; network rolling-hour limits remain and
storage accounting measures retained evidence. The superuser-only domain catalogue
stores aggregate DNS/attributed-flow counts and bounded hostname/CNAME examples for
manual alias review. Temporary transactional checkpoints expire with raw sources.
See `docs/implementation-guides/lab-demo.md` for deployment and physical acceptance.
