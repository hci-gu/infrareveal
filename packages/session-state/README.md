# `@infrareveal/session-state`

Shared product API and session runtime for both InfraReveal dashboards. This
package owns session manifests, revision subscriptions, bounded map-window caches,
activity pagination, capture semantics and playback state. Map projection and
animation belong to the dashboard.

```tsx
import { useSession, useMapWindow, useActivityBlocks } from '@infrareveal/session-state'

function SessionTraffic({ id, fromMs, toMs }: { id: string; fromMs: number; toMs: number }) {
  const { timeline } = useSession(id)
  const { window, loading, refreshing, error } = useMapWindow(id, fromMs, toMs)
  const { items: blocks } = useActivityBlocks(id, fromMs, toMs, 'latest')
  // Render using absolute epoch-millisecond bounds and the loaded snapshot.
  // `timeline.manifest` supplies retention, capture health and revision.
  return <div aria-busy={loading || refreshing}>{error || `${window.series.length} series, ${blocks.length} blocks in ${timeline.manifest?.name ?? id}`}</div>
}
```

`useSession` owns a reference-counted revision stream. Map windows publish complete
page sets and retain the last successful snapshot during related live refreshes;
loading, refreshing and errors remain explicit. Retention clips expired samples,
and session/capture changes invalidate continuity. Window caches are bounded to
twelve entries and an estimated 12 MiB. Activity pages use the same revision and
continuity rules. `setTimelinePlayback` updates shared cursor, playback and rate;
renderers interpolate time without publishing React state every frame.

Set `VITE_POCKETBASE_URL` in the consuming dashboard's `.env.local` to override
the default gateway on port `8090`. The session list expects the product API's
`{ items }` response. Both live and recorded sessions use this API.

Run `corepack pnpm --filter @infrareveal/session-state test` from the repository
root. Contract and runtime continuity tests cover retention, capture resets,
request races, outages, recovery, revision coalescing and API pagination.
