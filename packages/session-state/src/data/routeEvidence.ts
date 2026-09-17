import type { Flow, Route } from './types'
import { parseEpoch } from '../timeline/domain/time'

export const routeAvailableAt = (route: Route) => parseEpoch(route.available_at || route.completed_at, Infinity)
export const routeBindingKey = (route: Pick<Route, 'session' | 'destination_ip' | 'destination_port' | 'protocol'>) =>
  `${route.session}|${route.destination_ip}|${route.protocol.toLowerCase()}|${route.destination_port}`
export const compareRouteRevisions = (a: Route, b: Route) => routeAvailableAt(a) - routeAvailableAt(b) || a.id.localeCompare(b.id)
export function routeMatchesFlow(route: Route, flow: Pick<Flow, 'session' | 'destination_ip' | 'destination_port' | 'protocol'>) {
  return routeBindingKey(route) === routeBindingKey(flow)
}
export function routeIsValidAt(route: Route, cursorMs: number) {
  return routeAvailableAt(route) <= cursorMs && route.status !== 'invalidated'
    && (!route.valid_until || cursorMs < parseEpoch(route.valid_until, Infinity))
}
/** Select latest knowledge first, then validity. Never resurrect an older path
 * when a newer revision invalidates it or expires. */
export function routeForFlowAt(flow: Pick<Flow, 'session' | 'destination_ip' | 'destination_port' | 'protocol'>, routes: readonly Route[], cursorMs: number): Route | null {
  let latest: Route | null = null
  for (const route of routes) {
    if (routeMatchesFlow(route, flow) && routeAvailableAt(route) <= cursorMs && (!latest || compareRouteRevisions(route, latest) > 0)) latest = route
  }
  if (!latest) return null
  const projected = applyRouteEvidenceAt(latest, cursorMs)
  return routeIsValidAt(projected, cursorMs) ? projected : null
}
export function routeStateLabel(route: Route, cursorMs: number) {
  if (!routeIsValidAt(route, cursorMs)) return 'Route expired'
  const reached = route.destination_reached ?? route.complete
  const replies = route.responding_hops ?? route.hops?.filter(h => h.address && !h.missing).length ?? 0
  const gaps = route.hops?.some(h => h.missing || !h.address)
  const ageMs = cursorMs - parseEpoch(route.measured_at || route.completed_at, cursorMs)
  const age = ageMs < 60_000 ? `${Math.max(0, Math.floor(ageMs / 1000))}s` : `${Math.floor(ageMs / 60_000)}m`
  const state = route.status === 'queued' ? 'Queued' : route.status === 'probing' ? 'Discovering' : route.status === 'refreshing' ? (route.probe_details?.latest_attempt?.profile === 'coverage' ? 'Improving coverage' : 'Refreshing') : reached ? (gaps ? 'Reached · gaps' : 'Reached') : replies ? 'Partial route' : 'Route unavailable'
  const historical = route.fresh_until && cursorMs >= parseEpoch(route.fresh_until, Infinity) ? ' · historical approximation' : ''
  return `${state}${historical}${route.provenance === 'cache' || route.status === 'cached' ? ` · cached ${age} ago` : ''}`
}

export function previousRouteForFlowAt(flow: Pick<Flow, 'session' | 'destination_ip' | 'destination_port' | 'protocol'>, routes: readonly Route[], cursorMs: number): Route | null {
  const current = routeForFlowAt(flow, routes, cursorMs)
  if (!current) return null
  return routes.filter(route => route.id !== current.id && routeMatchesFlow(route, flow) && routeAvailableAt(route) <= cursorMs)
    .map(route => applyRouteEvidenceAt(route, cursorMs))
    .filter(route => routeIsValidAt(route, cursorMs) && route.hops?.some(hop => hop.address && hop.address !== route.destination_ip))
    .sort((a,b) => (b.responding_hops ?? 0)-(a.responding_hops ?? 0) || compareRouteRevisions(b,a))[0] ?? null
}

/** All consumers project the same immutable knowledge at the cursor. */
export function applyRouteEvidenceAt(route: Route, cursorMs: number): Route {
  let result = route
  for (const event of [...(route.evidence_updates ?? [])].sort((a,b) => parseEpoch(a.available_at, Infinity)-parseEpoch(b.available_at, Infinity))) {
    const at = parseEpoch(event.available_at, Infinity)
    if (at > cursorMs || at < routeAvailableAt(route)) continue
    if (event.kind === 'network_invalidated') return {...result, status:'invalidated'}
    if (event.kind === 'confirmed') result = {...result, fresh_until: String(event.value.fresh_until || result.fresh_until || ''), valid_until: String(event.value.valid_until || result.valid_until || '')}
    if (event.kind === 'enriched') result = {...result, hops: result.hops?.map(hop => ({...hop, interface_evidence: (event.value[String(hop.ttl)] as NonNullable<Route['hops']>[number]['interface_evidence']) ?? hop.interface_evidence})) ?? null}
  }
  return result
}

export function routeTopology(route: Route) {
  const groups: Array<{from: number; to: number; label: string; state: string; addresses: string[]}> = []
  for (const hop of [...(route.hops ?? [])].sort((a,b)=>a.ttl-b.ttl)) {
    const addresses = [...new Set([hop.address, ...(hop.replies?.map(reply=>reply.address) ?? [])].filter(Boolean))]
    const state = addresses.length ? (addresses.length > 1 ? 'ambiguous' : 'reply') : hop.state || 'unknown'
    const last = groups[groups.length - 1]
    if (!addresses.length && last?.state === state && last.to+1===hop.ttl) {last.to=hop.end_ttl ?? hop.ttl; continue}
    groups.push({from:hop.ttl,to:hop.end_ttl ?? hop.ttl,state,addresses,label:addresses.length ? addresses.join(' / ') : state==='not_probed' ? 'Not probed' : state==='no_reply' ? 'Unobserved segment' : 'Unknown segment'})
  }
  return groups
}

export const routeCollectionStateLabel = (state?: string) => ({
 probing:'Measuring this destination', low_activity:'Not selected: low activity', not_selected:'Not selected for measurement',
 target_budget:'Target budget reached', session_budget:'Attempt budget reached', hourly_budget:'Hourly budget reached', storage_budget:'Evidence budget reached',
 negative_cache:'Previous probes added no useful path', visibility_paused:'No additional path visibility under tested methods',
 comparison_finished:'Automatic comparison finished', useful_path_saved:'Useful approximation retained', engine_unavailable:'Measurement engine unavailable',
 network_unavailable:'Gateway source network unavailable; measurement paused',
 no_path:'Path not observable with these probes', access_only:'Access interfaces observed; remote path unknown', endpoint_only:'Destination responded; intermediate path unknown', indeterminate:'Measurement unfinished or unavailable', disabled:'Route collection disabled', manual_budget:'Manual measurement budget reached',
}[state || ''] || 'Destination known; intermediate route unknown')
