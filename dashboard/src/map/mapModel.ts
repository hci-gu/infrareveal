import { seriesKey, serviceKey, trafficTotals } from '@infrareveal/session-state'
import type { MapWindow, SessionManifest } from '@infrareveal/session-state'
import { hasMapCoordinates } from './mapCoordinates'
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
  country?: CountryFootprint | null
}

export type MapFrame = {
  points: MapPoint[]
  arcs: MapArc[]
  seenSeriesCount: number
  activeSeriesCount: number
  byteCount: number
}

const ACTIVE_TRAIL_MS = 5_000
const MAX_CONNECTIONS = 4_000


/** Group captured aggregates by their exact endpoint/version/service binding. */
export function buildMapTimelineScene(window: MapWindow, manifest: SessionManifest | null, origin: GatewayOrigin): MapTimelineScene {
  const destinations = new Map(window.destinations.map(value => [value.id, value]))
  const grouped = new Map<string, typeof window.series>()
  for (const chunk of window.series) { const key = seriesKey(chunk); const list = grouped.get(key) ?? []; list.push(chunk); grouped.set(key, list) }
  const endpoints: MapEndpoint[] = []
  for (const [id, chunks] of grouped) {
    chunks.sort((a,b) => a.start_ms - b.start_ms)
    const chunk = chunks[0], destination = destinations.get(chunk.destination_id)
    const position: MapPosition = [destination?.lon ?? NaN, destination?.lat ?? NaN]
    const country = countryFootprint({ city: destination?.city || '', country: destination?.country || '', position })
    if (!hasMapCoordinates(position[1], position[0]) && !country?.polygons.length) continue
    const firstSeenMs = Math.min(...chunks.map(value => value.start_ms + (value.samples[0]?.[0] ?? 0)))
    const lastSeenMs = Math.max(...chunks.map(value => value.start_ms + (value.samples[value.samples.length - 1]?.[0] ?? 0) + value.bucket_ms))
    const totals = trafficTotals(chunks, window.from_ms, window.to_ms)
    endpoints.push({ id, trackId: serviceKey(chunk), ip: chunk.destination_ip, label: chunk.service_label || destination?.ptr || chunk.destination_ip, provider: destination?.provider || '', city: destination?.city || '', country: destination?.country || '', position,
      availableFromMs: Math.max(firstSeenMs, destination?.observed_ms ?? Infinity), firstSeenMs, lastSeenMs,
      series: [{ id, startMs: firstSeenMs, endMs: lastSeenMs, bytes: totals.sent + totals.received, packets: totals.packetsSent + totals.packetsReceived }] })
  }
  endpoints.sort((a,b) => a.firstSeenMs-b.firstSeenMs || a.id.localeCompare(b.id))
  return { sessionId: manifest?.id ?? null, sessionName: manifest?.name || 'InfraReveal session', startMs: manifest?.retained_from_ms ?? window.from_ms, endMs: manifest?.active ? manifest.server_ms : manifest?.ended_ms || window.to_ms, origin, endpoints, totalSeriesCount: grouped.size }
}
/** Selects only what can be known and shown at the current session time. */
export function projectMapFrame(
  scene: MapTimelineScene,
  cursorMs: number,
  activeTrailMs = ACTIVE_TRAIL_MS,
  maximumConnections = MAX_CONNECTIONS,
): MapFrame {
  const points: MapPoint[] = []
  const connectedEndpoints: Array<{ endpoint: MapEndpoint; point: MapPoint }> = []
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

    const country = countryFootprint(endpoint)
    const point: MapPoint = {
      id: endpoint.id,
      trackId: endpoint.trackId,
      ip: endpoint.ip,
      label: endpoint.label,
      provider: endpoint.provider,
      location: [endpoint.city, endpoint.country].filter(Boolean).join(', '),
      position: country?.position ?? endpoint.position,
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
    })
  }

  connectedEndpoints.sort((left, right) =>
    right.point.activeSeriesCount - left.point.activeSeriesCount
    || right.point.bytes - left.point.bytes
    || left.endpoint.ip.localeCompare(right.endpoint.ip),
  )

  const arcs: MapArc[] = []
  for (const { endpoint, point } of connectedEndpoints) {
    if (arcs.length >= maximumConnections) break
    if (!hasMapCoordinates(point.position[1], point.position[0])) continue
    arcs.push({
      id: endpoint.id,
      trackId: endpoint.trackId,
      endpointId: endpoint.id,
      sourcePosition: originPosition(scene.origin),
      targetPosition: point.position,
      activeSeriesCount: point.activeSeriesCount,
      bytes: point.bytes,
      tilt: deterministicTilt(endpoint.ip),
      country: point.country,
    })
  }

  return { points, arcs, seenSeriesCount, activeSeriesCount, byteCount }
}

function originPosition(origin: GatewayOrigin): MapPosition {
  return [origin.longitude, origin.latitude]
}

function deterministicTilt(value: string) {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0
  return (Math.abs(hash) % 21) - 10
}
