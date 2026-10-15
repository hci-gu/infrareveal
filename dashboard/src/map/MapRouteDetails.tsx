import type { RouteEvidence } from '@infrareveal/session-state'
import { routeStateLabel } from '@infrareveal/session-state'
import { hasMapCoordinates, orderedRouteHops } from './mapRoutes'
import { formatCursor } from './format'
export function MapRouteDetails({ route, cursorMs = route.available_ms }: { route: RouteEvidence; cursorMs?: number }) {
  const hops = orderedRouteHops(route)
  return <details className="atlas-route-details"><summary>Measured route · {routeStateLabel(route, cursorMs)}<small>{formatCursor(route.measured_ms)} UTC · {route.method}</small></summary>
    <p className="atlas-route-explanation">Located interface IPs approximate the gateway's outward path. Dashed spans are unknown. The return path is unmeasured.</p>
    <ol className="atlas-route-hops">{hops.map((hop, index) => <li key={`${hop.ttl}:${index}`} value={hop.ttl} className={hasMapCoordinates(hop.lat, hop.lon) ? 'is-located' : 'is-unlocated'}><span className="atlas-hop-ttl">{hop.ttl}{hop.end_ttl ? `–${hop.end_ttl}` : ''}</span><span className="atlas-hop-description"><strong>{hop.state === 'not_probed' ? 'Not probed' : hop.missing ? 'Unobserved segment' : hop.hostname || hop.address || 'Unknown responder'}</strong><small>{[hop.city, hop.country].filter(Boolean).join(', ') || 'Location unavailable'}</small>{hop.state === 'multipath' && <small>Multiple responders: {[...new Set(hop.replies?.map(reply => reply.address) ?? [])].join(', ')}</small>}</span><span className="atlas-hop-rtt">{hop.timings?.length ? `${Math.min(...hop.timings).toFixed(1)} ms` : '—'}</span></li>)}</ol>
    {route.reason && <p>{route.reason}</p>}<small>Available {formatCursor(route.available_ms)} · expires {formatCursor(route.valid_until_ms)} UTC</small>
  </details>
}
