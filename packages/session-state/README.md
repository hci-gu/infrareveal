# `@infrareveal/session-state`

Shared session runtime for the regular and debug InfraReveal dashboards.

The package owns the PocketBase session transport, normalized entity store,
temporal indexes, realtime reconciliation, detail-page cache, playback state,
and React hooks. UI and Remotion scene projection stay inside each dashboard.

```tsx
import { useGatewayData } from '@infrareveal/session-state'

const { data, connectionState, timeline } = useGatewayData()
```

Set `VITE_POCKETBASE_URL` in either dashboard when PocketBase is not available
at port `8090` on the dashboard host. Both live and recorded sessions use the
same hook and epoch-millisecond timeline.
