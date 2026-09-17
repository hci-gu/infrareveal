# Developer documentation

Start with the [project README](../README.md) for setup and deployment, [CONTEXT.md](../CONTEXT.md) for domain boundaries, and the [debug dashboard README](../debug-dashboard/README.md) for workspace behavior and local fixtures.

## Architecture decisions

- [Metadata gateway, not transparent TLS proxy](adr/0001-metadata-gateway-not-transparent-tls-proxy.md): observation scope and privacy boundaries.
- [Opt-in NFQUEUE flow admission](adr/0002-opt-in-nfqueue-flow-admission.md): experimental control policy and fail-open requirements.

## Implementation and operations

- [Two-network Pi deployment](implementation-guides/pi-deployment.md): admin Wi-Fi, local UI/API hosting, ARMv7/ARM64 builds, migration and updates.

- [Flow activity bursts](implementation-guides/flow-activity-bursts.md): capture, aggregation, persistence, quality and visualization contracts.
- [Proxy Lab](implementation-guides/proxy-lab.md): runtime components, control APIs, first run and emergency recovery.
- [Live route discovery](implementation-guides/live-route-discovery.md): scheduling, cache reuse, progressive evidence, replay and diagnostics.

## Validation procedures

- [Dashboard browser checks](validation/debug-dashboard.md): fixtures, interaction, accessibility, performance and lifecycle checks.
- [Flow activity on Raspberry Pi](validation/flow-activity-raspberry-pi.md): raw capture, timing, privacy and resource measurements.
- [Proxy Lab on Raspberry Pi](validation/proxy-lab-raspberry-pi.md): namespace, failure, soak, client and recovery checks.
- [Live route discovery](validation/live-route-discovery.md): timing targets, cache/replay scenarios and pending Pi measurements.

## Domain grouping

- [Domain grouping](implementation-guides/domain-grouping.md): automatic registered-domain groups, explicit JSON aliases, and session lifecycle.

## Keeping this folder useful

Keep current contracts, decisions, operator instructions and repeatable validation procedures here. Update the relevant guide when an implementation changes. Identify proposed behavior and pending hardware acceptance explicitly.

Put generated screenshots, logs, data exports and benchmark results under `output/` or attach them to the relevant issue or release. Completed task checklists and implementation handoff reports belong in version history; carry their lasting decisions and unresolved checks into the guides above.
