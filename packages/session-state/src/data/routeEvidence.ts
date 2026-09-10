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
  return latest && routeIsValidAt(latest, cursorMs) ? latest : null
}
export function routeStateLabel(route: Route, cursorMs: number) {
  if (!routeIsValidAt(route, cursorMs)) return 'Route expired'
  const reached = route.destination_reached ?? route.complete
  const replies = route.responding_hops ?? route.hops?.filter(h => h.address && !h.missing).length ?? 0
  const gaps = route.hops?.some(h => h.missing || !h.address)
  const ageMs = cursorMs - parseEpoch(route.measured_at || route.completed_at, cursorMs)
  const age = ageMs < 60_000 ? `${Math.max(0, Math.floor(ageMs / 1000))}s` : `${Math.floor(ageMs / 60_000)}m`
  const state = route.status === 'queued' ? 'Queued' : route.status === 'probing' ? 'Discovering' : route.status === 'refreshing' ? (route.probe_details?.latest_attempt?.profile === 'coverage' ? 'Improving coverage' : 'Refreshing') : reached ? (gaps ? 'Reached · gaps' : 'Reached') : replies ? 'Partial route' : 'Route unavailable'
  return `${state}${route.provenance === 'cache' || route.status === 'cached' ? ` · cached ${age} ago` : ''}`
}
