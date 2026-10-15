# ADR 0003: Store aggregate traffic and temporal activity blocks

Date: 2026-10-15

## Status

Accepted. This is the implementation standard for the direct rewrite.

## Context

The product displays traffic on a map and groups it into understandable periods
of service activity. Nineteen application collections currently expose collector
stages and duplicated route state. The browser reconstructs those stages, while
permanent domain groups cannot express separate visits after inactivity.

## Decision

Use seven core collections: `sessions`, `traffic_chunks`, `capture_intervals`,
`activity_blocks`, `destinations`, `route_evidence` and `probe_runs`.

Aggregate captured counters across compatible connections by client, service,
exact endpoint binding, destination version and time. Retain fine directional
samples and independent capture coverage. Connection/DNS correlation is bounded
in memory. Persist small evidence summaries with the classification; freeze
classification after the provisional tail. Correcting that tail is atomic.

Derive temporal activity blocks from qualifying sample intervals and a quiet-gap
heuristic. Keep span, active-time union, captured bytes and uncertainty separate.
Do not infer browser attention or join different services merely because they
share an IP, provider or time window.

Separate historical route evidence from operational probe admission. Charge
attempts before launch, retain shared-network quotas across restart/deletion,
publish only useful terminal paths and typed invalidations, and reuse only
same-session/network-epoch evidence. Bound optional enrichment and diagnostics.

Provide product-shaped bounded map windows and one session revision signal to
both dashboards. Delete collector-level joins and collection subscriptions.

Full diagnostics adds `flow_diagnostics`, `dns_queries` and `gate_events` with
independent time/byte limits. Raw payload content is never stored. The Lab gate
remains explicitly enabled and fail-open and requires its audit storage.

Implement directly against a fresh application schema. There are no old-data
converters, dual writers, legacy API adapters or shadow deployment. Development
recordings are disposable. The previous source remains available in Git.

## Consequences

Core mode cannot reconstruct complete raw connection history or reattribute all
sealed bytes. Captured activity is not measured browsing attention. A new session
may lack route paths while shared-network budgets are exhausted. These are
accepted product tradeoffs for simpler persistence and bounded work.

Traffic/capture durability, byte conservation, route replay, admission limits and
rolling retention remain correctness requirements. Optional diagnostics and
route collection cannot block normal gateway forwarding.

This supersedes ADR 0001's separate persisted attribution/connection model while
retaining its metadata-only gateway decision. ADR 0002's gate safety and audit
requirements remain in force. Execution is tracked in the root implementation
checklist, rather than through a compatibility rollout.
