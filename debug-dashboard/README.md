# InfraReveal activity and gateway laboratory

The session library uses the public product session API. Start a session, end an
active capture, then open **Activity** or **Lab**. Configure `VITE_POCKETBASE_URL`
when the gateway is not on the default port 8090.

```sh
corepack pnpm install
corepack pnpm --filter @infrareveal/debug-dashboard dev
```

## Activity

`/timeline/:sessionID` reads the same manifest and revision stream as the map.
A bounded 1, 5 or 30 minute window contains aggregate traffic samples, capture
intervals, versioned destinations and as-known route publications. Captured wire
samples are the only source for totals, including ACK-only traffic outside blocks.
Missing capture is not presented as confirmed silence.

The paged block browser groups service activity by client and time, splitting
quiet gaps. Selecting a block seeks playback and shows its original/retained
interval, active time, confidence, quality and captured totals. Block details load
one bounded minute of endpoint and classification evidence around the playhead.
A block can span several connections, and one connection can span several blocks;
no individual connection records are reconstructed for this view.

Optional diagnostics are a separate authenticated read. Flow, DNS and gate data
show **not recorded** when their collection was absent for the session. Tokens are
kept in component memory. The default installation and activity UI work without
raw diagnostic collections.

## Laboratory

`/proxy-lab/:sessionID` preserves the gateway graph, trace selection, node
inspection, replay, frame steps, direction, reduced motion, pan and zoom. Recorded
core events are captured aggregate bursts and route publications. Intermediate
node motion illustrates forwarding topology; it is not a measured packet path.
The optional live diagnostic stream is kept separate from persisted product facts.

Live gate controls require their configured diagnostics/audit profile and explicit
authenticated arming. The NOW queue uses the current server clock even when replay
is paused. Approve/reject, strict stepping, pause/resume, drain and disarm retain
the gateway's fail-open controls. Gate history availability and audit completeness
are separate from capture and browser-stream health.

The old collection joins, connection ledger, separate activity summary transport,
Remotion treemap/export path and historical compatibility layer have been removed.
Both apps share the new manifest/window/block runtime and its bounded cache.

Run `corepack pnpm test`, `corepack pnpm lint`, and `corepack pnpm build` here.
The [real API browser smoke check](../dashboard/test-support/README.md) covers both
apps. `testdata/aggregate-window-v2.json` contains aggregate fixtures using supported
DNS-answer attribution, independent endpoints, separated service blocks and route
publications; it is never loaded by production application code.
