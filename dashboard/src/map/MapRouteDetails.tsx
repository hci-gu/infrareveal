import type { Route } from '@infrareveal/session-state'
import { parseEpoch, routeStateLabel, routeAvailableAt } from '@infrareveal/session-state'
import { hasMapCoordinates, orderedRouteHops } from './mapRoutes'
import { formatCursor } from './format'

export function MapRouteDetails({ route, cursorMs = routeAvailableAt(route) }: { route: Route; cursorMs?: number }) {
  const hops = orderedRouteHops(route)
  const replies = hops.filter(hop => !hop.missing && hop.address)
  const located = replies.filter(hop => hasMapCoordinates(hop.lat, hop.lon))
  return <details className="atlas-route-details">
    <summary><span>Traceroute <b>{routeStateLabel(route, cursorMs)}</b></span><small>{replies.length} replies · {located.length} located · {formatCursor(parseEpoch(route.measured_at || route.completed_at || route.available_at, 0))} UTC</small></summary>
    <p className="atlas-route-explanation">Located routers shape the map path. Dashed spans bridge unanswered or unlocated hops; their path is approximate.</p>
    <ol className="atlas-route-hops">{hops.map((hop, i) => {
      const timings = (hop.timings ?? []).filter(value => Number.isFinite(value) && value >= 0)
      const located = !hop.missing && hasMapCoordinates(hop.lat, hop.lon)
      return <li key={`${hop.ttl}:${i}`} className={located ? 'is-located' : 'is-unlocated'} value={hop.ttl}>
        <span className="atlas-hop-ttl">{hop.ttl}</span>
        <span className="atlas-hop-description">
          <strong>{hop.state === 'not_probed' ? 'Not probed' : hop.state === 'pending' ? 'Awaiting reply' : hop.missing ? 'No response' : hop.hostname || hop.address || 'Unknown responder'}</strong>
          {!hop.missing && hop.hostname && hop.hostname !== hop.address && <small>{hop.address}</small>}
          <small>{located ? [hop.city, hop.country].filter(Boolean).join(', ') || 'Approximate location' : hop.missing ? 'Path unknown' : 'Location unavailable'}</small>
          {located && hop.accuracy_km != null && <small>GeoIP estimate · {hop.accuracy_km} km radius</small>}
        </span>
        <span className="atlas-hop-rtt">{timings.length ? `${Math.min(...timings).toFixed(1)} ms` : '—'}</span>
      </li>
    })}</ol>
    {hops.length === 0 && <p>No hop responses were saved for this probe.</p>}
    {route.provenance === 'alternate' && <p>Alternate probe method; this path is an approximation for the observed traffic.</p>}
    {route.error && <p>{route.error}</p>}
    <small>Incoming volume follows this gateway-measured path; the return path is unmeasured.</small>
    <small>Gateway probe · {route.method} · reply times are round trips from the gateway</small>
  </details>
}
