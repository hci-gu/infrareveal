import type { Destination, Route } from '@infrareveal/session-state'
import { routeAvailableAt } from '@infrareveal/session-state'
import type { GatewayOrigin, MapPosition, MapRoutePath } from './mapModel'
import { isCountryLocation } from './countryFootprints'

export type RouteNode = {
  position: MapPosition
  kind: 'gateway' | 'hop' | 'destination'
  ttl: number
  address: string
  label: string
  rttMs: number | null
}

export function hasMapCoordinates(lat: unknown, lon: unknown): boolean {
  return typeof lat === 'number' && typeof lon === 'number' && Number.isFinite(lat) && Number.isFinite(lon)
    && lat >= -90 && lat <= 90 && lon >= -180 && lon <= 180 && (lat !== 0 || lon !== 0)
}

export function orderedRouteHops(route: Route) {
  return [...(route.hops ?? [])].filter(hop => Number.isInteger(hop.ttl) && hop.ttl > 0).sort((a, b) => a.ttl - b.ttl)
}

/** Preserve unanswered/unlocated spans without placing private or unknown routers at 0,0. */
export function mapRoutePath(route: Route, origin: GatewayOrigin, destination: Destination): MapRoutePath {
  const location = route.available_at ? route.destination_location : destination
  const destinationLocated = hasMapCoordinates(location?.lat, location?.lon)
  const nodes: RouteNode[] = [{ position: [origin.longitude, origin.latitude], kind: 'gateway', ttl: 0, address: '', label: origin.label, rttMs: null }]
  const gaps: boolean[] = []
  const hops = orderedRouteHops(route)
  let previousTTL = 0
  let gap = false
  const add = (node: RouteNode, inferred: boolean) => {
    const previous = nodes[nodes.length - 1]
    if (previous.position[0] === node.position[0] && previous.position[1] === node.position[1]) {
      if (node.kind === 'destination') nodes[nodes.length - 1] = node
      return
    }
    nodes.push(node)
    gaps.push(inferred)
  }
  for (const hop of hops) {
    gap ||= hop.ttl > previousTTL + 1 || hop.state === 'multipath'
    previousTTL = hop.ttl
    if (hop.missing || !hop.address || !hasMapCoordinates(hop.lat, hop.lon)) { gap = true; continue }
    if (isCountryLocation(hop) && hop.address !== route.destination_ip) { gap = true; continue }
    const destinationHop = hop.address === route.destination_ip
    const timings = (hop.timings ?? []).filter(value => Number.isFinite(value) && value >= 0)
    add({
      position: destinationHop && destinationLocated ? [location!.lon, location!.lat] : [hop.lon!, hop.lat!],
      kind: destinationHop ? 'destination' : 'hop', ttl: hop.ttl, address: hop.address,
      label: [hop.city, hop.country].filter(Boolean).join(', ') || hop.hostname || hop.address,
      rttMs: timings.length ? Math.min(...timings) : null,
    }, gap)
    gap = hop.state === 'multipath'
    if (destinationHop) break
  }
  if (nodes[nodes.length - 1].kind !== 'destination' && destinationLocated) {
    const reply = hops.find(hop => !hop.missing && hop.address === route.destination_ip)
    add({ position: [location!.lon, location!.lat], kind: 'destination', ttl: reply?.ttl ?? previousTTL + 1, address: route.destination_ip, label: destination.city || destination.country || route.destination_ip, rttMs: reply?.timings?.find(value => Number.isFinite(value) && value >= 0) ?? null }, true)
  }
  return { id: route.id, evidence: route, completedAtMs: routeAvailableAt(route), positions: nodes.map(node => node.position), nodes, gaps, complete: route.complete }
}

/** One phase spans the entire displayed route instead of restarting at every router. */
export function routeProgress(positions: MapPosition[]): number[] {
  const lengths = positions.slice(1).map((point, i) => angularDistance(positions[i], point))
  const total = lengths.reduce((sum, length) => sum + length, 0)
  let distance = 0
  return [0, ...lengths.map((length, i) => { distance += length; return total > 0 ? distance / total : (i + 1) / lengths.length })]
}

function angularDistance(a: MapPosition, b: MapPosition) {
  const radians = Math.PI / 180
  const lat = (b[1] - a[1]) * radians, lon = (b[0] - a[0]) * radians
  const h = Math.sin(lat / 2) ** 2 + Math.cos(a[1] * radians) * Math.cos(b[1] * radians) * Math.sin(lon / 2) ** 2
  return 2 * Math.asin(Math.sqrt(Math.min(1, Math.max(0, h))))
}
