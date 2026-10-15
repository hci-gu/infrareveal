import { routeForSeriesAt, seriesKey, serviceKey, trafficTotals } from '@infrareveal/session-state'
import type { MapWindow, SessionManifest, RouteEvidence } from '@infrareveal/session-state'
import { hasMapCoordinates, mapRoutePath, routeProgress } from './mapRoutes'
import type { RouteNode } from './mapRoutes'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
export type MapPosition = [longitude: number, latitude: number]

export type GatewayOrigin = {
  latitude: number
  longitude: number
  label: string
}

export type MapSeriesInterval = {
  id: string
  startMs: number
  endMs: number
  bytes: number
  packets: number
  bytesIn?: number
  bytesOut?: number
  packetsIn?: number
  packetsOut?: number
}

export type MapRoutePath = {
  evidence: RouteEvidence
  id: string
  completedAtMs: number
  positions: MapPosition[]
  nodes: RouteNode[]
  gaps: boolean[]
  complete: boolean
}

export type MapHopPoint = RouteNode & { id: string; trackId?: string; routeId: string }

export type MapEndpoint = {
  id: string
  trackId?: string
  ip: string
  label: string
  provider: string
  city: string
  country: string
  position: MapPosition
  availableFromMs: number
  firstSeenMs: number
  lastSeenMs: number
  series: MapSeriesInterval[]
  routes: MapRoutePath[]
  invalidations: RouteEvidence[]
}

export type MapTimelineScene = {
  sessionId: string | null
  sessionName: string
  startMs: number
  endMs: number
  origin: GatewayOrigin
  endpoints: MapEndpoint[]
  totalSeriesCount: number
}

export type MapPoint = {
  id: string
  trackId?: string
  ip: string
  label: string
  provider: string
  location: string
  position: MapPosition
  seriesCount: number
  activeSeriesCount: number
  bytes: number
  country?: CountryFootprint | null
}

export type MapArc = {
  id: string
  trackId?: string
  endpointId: string
  sourcePosition: MapPosition
  targetPosition: MapPosition
  activeSeriesCount: number
  bytes: number
  tilt: number
  routeId?: string
  gap?: boolean
  progressStart?: number
  progressEnd?: number
  country?: CountryFootprint | null
}

export type MapFrame = {
  points: MapPoint[]
  arcs: MapArc[]
  hops: MapHopPoint[]
  seenSeriesCount: number
  activeSeriesCount: number
  byteCount: number
}

const ACTIVE_TRAIL_MS = 5_000
const MAX_ARC_SEGMENTS = 4_000


/** Group captured aggregates by their exact endpoint/version/service binding. */
export function buildMapTimelineScene(window: MapWindow, manifest: SessionManifest | null, origin: GatewayOrigin): MapTimelineScene {
  const destinations = new Map(window.destinations.map(value => [value.id, value]))
  const grouped = new Map<string, typeof window.series>()
  for (const chunk of window.series) { const key = seriesKey(chunk); const list = grouped.get(key) ?? []; list.push(chunk); grouped.set(key, list) }
  const endpoints: MapEndpoint[] = []
  for (const [id, chunks] of grouped) {
    chunks.sort((a,b) => a.start_ms - b.start_ms)
    const chunk = chunks[0], destination = destinations.get(chunk.destination_id)
    const paths = window.routes.filter(route => route.kind === 'path' && route.session === chunk.session && route.destination_ip === chunk.destination_ip && route.protocol === chunk.protocol && route.destination_port === chunk.destination_port && route.network_epoch === chunk.network_epoch)
    const position: MapPosition = [destination?.lon ?? NaN, destination?.lat ?? NaN]
    const country = countryFootprint({ city: destination?.city || '', country: destination?.country || '', position })
    if (!hasMapCoordinates(position[1], position[0]) && !country?.polygons.length && !paths.some(path => path.hops.some(hop => hasMapCoordinates(hop.lat,hop.lon)))) continue
    const firstSeenMs = Math.min(...chunks.map(value => value.start_ms + (value.samples[0]?.[0] ?? 0)))
    const lastSeenMs = Math.max(...chunks.map(value => value.start_ms + (value.samples[value.samples.length - 1]?.[0] ?? 0) + value.bucket_ms))
    const totals = trafficTotals(chunks, window.from_ms, window.to_ms)
    const routes = destination ? paths.map(route => mapRoutePath(route, origin, destination)) : []
    endpoints.push({ id, trackId: serviceKey(chunk), ip: chunk.destination_ip, label: chunk.service_label || destination?.ptr || chunk.destination_ip, provider: destination?.provider || '', city: destination?.city || '', country: destination?.country || '', position,
      availableFromMs: Math.max(firstSeenMs, Math.min(destination?.observed_ms ?? Infinity, ...routes.map(route => route.completedAtMs))), firstSeenMs, lastSeenMs,
      series: [{ id, startMs: firstSeenMs, endMs: lastSeenMs, bytes: totals.sent + totals.received, packets: totals.packetsSent + totals.packetsReceived }], routes,
      invalidations: window.routes.filter(route => route.kind === 'network_invalidated' && route.network_epoch === chunk.network_epoch && route.session === chunk.session) })
  }
  endpoints.sort((a,b) => a.firstSeenMs-b.firstSeenMs || a.id.localeCompare(b.id))
  return { sessionId: manifest?.id ?? null, sessionName: manifest?.name || 'InfraReveal session', startMs: manifest?.retained_from_ms ?? window.from_ms, endMs: manifest?.active ? manifest.server_ms : manifest?.ended_ms || window.to_ms, origin, endpoints, totalSeriesCount: grouped.size }
}
/** Selects only what can be known and shown at the current session time. */
export function projectMapFrame(
  scene: MapTimelineScene,
  cursorMs: number,
  activeTrailMs = ACTIVE_TRAIL_MS,
  maximumArcSegments = MAX_ARC_SEGMENTS,
): MapFrame {
  const points: MapPoint[] = []
  const connectedEndpoints: Array<{ endpoint: MapEndpoint; point: MapPoint; route: MapRoutePath | null }> = []
  let seenSeriesCount = 0
  let activeSeriesCount = 0
  let byteCount = 0

  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > cursorMs || endpoint.firstSeenMs > cursorMs) continue
    let endpointSeenFlows = 0
    let endpointActiveFlows = 0
    let endpointBytes = 0

    for (const flow of endpoint.series) {
      if (flow.startMs > cursorMs) break
      endpointSeenFlows += 1
      endpointBytes += flow.bytes
      if (cursorMs <= flow.endMs + activeTrailMs) endpointActiveFlows += 1
    }
    if (endpointSeenFlows === 0) continue

    const route = latestAvailableRoute(endpoint, cursorMs)
    const location = route?.evidence?.destination_location
    const country = countryFootprint(endpoint)
    const point: MapPoint = {
      id: endpoint.id,
      trackId: endpoint.trackId,
      ip: endpoint.ip,
      label: endpoint.label,
      provider: endpoint.provider,
      location: [endpoint.city, endpoint.country].filter(Boolean).join(', '),
      position: country?.position ?? (location ? [location.lon, location.lat] : endpoint.position),
      country,
      seriesCount: endpointSeenFlows,
      activeSeriesCount: endpointActiveFlows,
      bytes: endpointBytes,
    }
    if (hasMapCoordinates(point.position[1], point.position[0])) points.push(point)
    seenSeriesCount += endpointSeenFlows
    activeSeriesCount += endpointActiveFlows
    byteCount += endpointBytes

    // Keep the connection visible while its volume can swell or fall back to zero.
    connectedEndpoints.push({
      endpoint,
      point,
      route,
    })
  }

  connectedEndpoints.sort((left, right) =>
    right.point.activeSeriesCount - left.point.activeSeriesCount
    || right.point.bytes - left.point.bytes
    || left.endpoint.ip.localeCompare(right.endpoint.ip),
  )

  const arcs: MapArc[] = []
  const hops = new Map<string, MapHopPoint>()
  for (const { endpoint, point, route } of connectedEndpoints) {
    let positions = route?.positions ?? (hasMapCoordinates(point.position[1], point.position[0]) ? [originPosition(scene.origin), point.position] : [])
    if (point.country) {
      // Retain located route evidence, but never route into a country centroid as a city.
      positions = route
        ? [...positions.slice(0, route.nodes[route.nodes.length - 1]?.kind === 'destination' ? -1 : undefined), point.country.position]
        : [originPosition(scene.origin), point.country.position]
    }
    // Keep complete paths when the display budget is exhausted.
    if (arcs.length + positions.length - 1 > maximumArcSegments) continue
    const progress = routeProgress(positions)
    for (let index = 1; index < positions.length && arcs.length < maximumArcSegments; index += 1) {
      arcs.push({
        id: `${endpoint.id}:${index}`,
        trackId: endpoint.trackId,
        endpointId: endpoint.id,
        sourcePosition: positions[index - 1],
        targetPosition: positions[index],
        activeSeriesCount: point.activeSeriesCount,
        bytes: point.bytes,
        tilt: deterministicTilt(endpoint.ip),
        routeId: route?.id,
        gap: route?.gaps[index - 1] ?? true,
        progressStart: progress[index - 1],
        progressEnd: progress[index],
        country: index === positions.length - 1 ? point.country : null,
      })
      const hop = route?.nodes[index]
      if (hop?.kind === 'hop') {
        const id = `${endpoint.trackId ?? ''}/${route!.id}/${hop.ttl}/${hop.address}`
        hops.set(id, { ...hop, id, trackId: endpoint.trackId, routeId: route!.id })
      }
    }
    if (arcs.length >= maximumArcSegments) break
  }

  return { points, arcs, hops: [...hops.values()], seenSeriesCount, activeSeriesCount, byteCount }
}


function latestAvailableRoute(endpoint: MapEndpoint, cursorMs: number) {
  const binding = endpoint.routes[0]?.evidence
  if (!binding) return null
  const latest = routeForSeriesAt(binding, [...endpoint.routes.map(path => path.evidence), ...endpoint.invalidations], cursorMs)
  return latest ? endpoint.routes.find(path => path.id === latest.id) ?? null : null
}
function originPosition(origin: GatewayOrigin): MapPosition {
  return [origin.longitude, origin.latitude]
}

function deterministicTilt(value: string) {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0
  return (Math.abs(hash) % 21) - 10
}
