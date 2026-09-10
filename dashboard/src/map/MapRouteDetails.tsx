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
    {route.probe_details?.profile === 'coverage' && <p>Coverage pass · {route.probe_details.probe_count} probes · {Math.round((route.probe_details.hop_coverage ?? 0) * 100)}% of probed hop positions answered.</p>}
    <ol className="atlas-route-hops">{hops.map((hop, i) => {
      const timings = (hop.timings ?? []).filter(value => Number.isFinite(value) && value >= 0)
      const located = !hop.missing && hasMapCoordinates(hop.lat, hop.lon)
      return <li key={`${hop.ttl}:${i}`} className={located ? 'is-located' : 'is-unlocated'} value={hop.ttl}>
        <span className="atlas-hop-ttl">{hop.ttl}</span>
        <span className="atlas-hop-description">
          <strong>{hop.state === 'not_probed' ? 'Not probed' : hop.state === 'pending' ? 'Awaiting reply' : hop.missing ? 'No response' : hop.hostname || hop.address || 'Unknown responder'}</strong>
          {hop.state === 'multipath' && <small>Multiple responders: {[...new Set(hop.replies?.map(reply => reply.address) ?? [])].join(', ')}. Connections through this hop are uncertain.</small>}
          {!hop.missing && hop.hostname && hop.hostname !== hop.address && <small>{hop.address}</small>}
          <small>{located ? [hop.city, hop.country].filter(Boolean).join(', ') || 'Approximate location' : hop.missing ? 'Path unknown' : 'Location unavailable'}</small>
          {located && hop.accuracy_km != null && <small>GeoIP estimate · {hop.accuracy_km} km radius</small>}
        </span>
        <span className="atlas-hop-rtt">{timings.length ? `${Math.min(...timings).toFixed(1)} ms` : '—'}</span>
      </li>
    })}</ol>
    {hops.length === 0 && <p>No hop responses were saved for this probe.</p>}
    {(route.provenance === 'alternate' || route.probe_details?.alternate_method) && <p>Alternate probe method; this path is an approximation for the observed traffic.</p>}
    {route.probe_details?.latest_attempt && route.probe_details.latest_attempt.method !== route.method && <p>Latest attempt: {route.probe_details.latest_attempt.method} · {route.probe_details.latest_attempt.status}. The map retains the best available measured path.</p>}
    {route.alternate_routes?.map(alternative => <details key={alternative.method}>
      <summary>{alternative.method} · {alternative.responding_hops} responding hops · {alternative.located_hops} located · {alternative.destination_reached ? 'Reached' : 'Partial'}</summary>
      <small>Measured {formatCursor(parseEpoch(alternative.measured_at, 0))} UTC. Separate measurement; hops are not combined with the displayed path.</small>
      <ol className="atlas-route-alternatives">{alternative.hops?.map(hop => <li key={hop.ttl} value={hop.ttl}>{hop.state === 'not_probed' ? 'Not probed' : hop.address || 'No reply'}{hop.city ? ` · ${hop.city}` : ''}{hop.state === 'multipath' && <small>Multiple responders: {[...new Set(hop.replies?.map(reply => reply.address) ?? [])].join(', ')}</small>}</li>)}</ol>
    </details>)}
    {route.error && <p>{route.error}</p>}
    <small>Incoming volume follows this gateway-measured path; the return path is unmeasured.</small>
    <small>Gateway probe · {route.method} · reply times are round trips from the gateway</small>
  </details>
}
