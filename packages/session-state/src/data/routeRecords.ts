import { parseEpoch } from '../timeline/domain/time'
import type { Route, RouteEvidenceUpdate } from './types'

export type RouteEvidenceRecord = RouteEvidenceUpdate & {
  id: string
  session: string
  network_context: string
  /** Historical wire name: this is a route record ID, not an endpoint tuple. */
  binding_key: string
}

type Hop = NonNullable<Route['hops']>[number]

/** Preserve legacy flat evidence and alternate probes. Structured replies fill
 * missing flat fields only when there is a single unambiguous address; they must
 * never turn multiple responders into an invented linear path. */
export function normalizeRouteRecord(route: Route, cursorMs = parseEpoch(route.available_at || route.completed_at, Infinity)): Route {
  const normalizeHops = (hops: Route['hops']) => hops?.map(hop => normalizeHop(hop, cursorMs)) ?? null
  return {
    ...route,
    complete: route.complete ?? route.destination_reached ?? false,
    hops: normalizeHops(route.hops),
    ...(route.alternate_routes ? {
      alternate_routes: route.alternate_routes.map(alternative => ({ ...alternative, hops: normalizeHops(alternative.hops) })),
    } : {}),
  }
}

function normalizeHop(hop: Hop, cursorMs: number): Hop {
  const replies = hop.replies ?? []
  const addresses = [...new Set(replies.map(reply => reply.address).filter(Boolean))]
  const address = hop.address || (addresses.length === 1 ? addresses[0] : '')
  const evidence = hop.interface_evidence?.[address]
  const geo = evidence?.geo && parseEpoch(evidence.geo_available_at || evidence.available_at, Infinity) <= cursorMs
    ? evidence.geo : undefined
  const timings = hop.timings ?? replies.filter(reply => reply.address === address)
    .map(reply => reply.reported_rtt_ms ?? reply.rtt_ms)
    .filter((value): value is number => typeof value === 'number' && Number.isFinite(value) && value >= 0)
  return {
    ...hop, address, timings,
    missing: hop.missing ?? !address,
    ...(geo ? {
      lat: hop.lat ?? geo.lat, lon: hop.lon ?? geo.lon,
      city: hop.city ?? geo.city, country: hop.country ?? geo.country,
      accuracy_km: hop.accuracy_km ?? geo.accuracy_km,
      geo_version: hop.geo_version ?? geo.geo_version,
    } : {}),
  }
}

function routeEvidenceApplies(route: Route, event: RouteEvidenceRecord) {
  if (event.session !== route.session) return false
  if (event.binding_key === route.id) return true
  return event.kind === 'network_invalidated' && event.network_context === route.network_context
    && parseEpoch(event.available_at, -Infinity) > parseEpoch(route.available_at || route.completed_at, Infinity)
}

function routeEvidenceValue(event: RouteEvidenceUpdate): RouteEvidenceUpdate {
  return { kind: event.kind, available_at: event.available_at, value: event.value }
}

export function routeEvidenceIdentity(event: RouteEvidenceUpdate) {
  return JSON.stringify(routeEvidenceValue(event))
}

/** Attach collection event rows using the same session, route and network rules
 * as timeline responses. Compare instants, never PocketBase/ISO timestamp strings. */
export function attachRouteEvidenceUpdates(routes: Route[], updates: RouteEvidenceRecord[]): Route[] {
  return routes.map(route => {
    const events = [...(route.evidence_updates ?? []), ...updates.filter(event => routeEvidenceApplies(route, event)).map(routeEvidenceValue)]
    return normalizeRouteRecord({ ...route, evidence_updates: [...new Map(events.map(event => [routeEvidenceIdentity(event), event])).values()] })
  })
}
