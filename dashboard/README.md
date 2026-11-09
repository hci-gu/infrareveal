# InfraReveal dashboard

The dashboard shows captured traffic on Equal Earth and Mercator maps, in a
fullscreen timeline, and in service/activity inspectors. Both projections share
filters, ordering, playback and inspection state through one workspace.

From the repository root:

```sh
corepack pnpm install
cp dashboard/.env.example dashboard/.env.local
corepack pnpm --filter @infrareveal/dashboard dev
```

Set `VITE_POCKETBASE_URL` in `.env.local` when the gateway is not at port `8090`
on the dashboard host. Restart Vite after changing environment variables. Local
environment files are ignored by Git; `.env.example` documents supported overrides.

Open `/` for sessions, `/map/:sessionID` for a recording or live session, and
`/demo` for the configured kiosk session. The top bar owns shared filters and
sorting. History defaults to five minutes; **Only active now** optionally limits
membership to endpoints active within fifteen seconds. Display settings contain
projection, appearance, labels and browser fullscreen. Rendering always uses
animations and the full graphics pipeline.

See the [map guide](../docs/implementation-guides/map-dashboard.md) for behavior
and architecture, and [browser checks](test-support/README.md) for validation.
The shared API/runtime lives in
[`@infrareveal/session-state`](../packages/session-state/README.md).

```sh
corepack pnpm --filter @infrareveal/dashboard test
corepack pnpm --filter @infrareveal/dashboard lint
corepack pnpm --filter @infrareveal/dashboard build
```
