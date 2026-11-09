import type { MapTrackCatalog } from './mapTracks'
import { serviceKey } from '@infrareveal/session-state'
import type { SessionManifest } from '@infrareveal/session-state'
import { hasMapCoordinates } from './mapCoordinates'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
export type MapPosition = [longitude: number, latitude: number]

export type GatewayOrigin = {
  latitude: number
  longitude: number
  label: string
}

type MapSeriesInterval = {
  id: string
  startMs: number
  endMs: number
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
  series: MapSeriesInterval[]
}

export type MapTimelineScene = {
  sessionId: string | null
  sessionName: string
  startMs: number
  endMs: number
  origin: GatewayOrigin
  endpoints: MapEndpoint[]
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
  country?: CountryFootprint | null
}

export type MapArc = {
  id: string
  trackId?: string
  endpointId: string
  sourcePosition: MapPosition
  targetPosition: MapPosition
  country?: CountryFootprint | null
}

type MapFrame = {
  points: MapPoint[]
  arcs: MapArc[]
}

const ACTIVE_TRAIL_MS = 5_000


/** Group captured aggregates by their exact endpoint/version/service binding. */
export function buildMapTimelineScene(catalog: MapTrackCatalog, manifest: SessionManifest | null, origin: GatewayOrigin): MapTimelineScene {
  const { grouped, destinations } = catalog
  const endpoints: MapEndpoint[] = []
  for (const [id, chunks] of grouped) {
    const chunk = chunks[0], destination = destinations.get(chunk.destination_id)
    const position: MapPosition = [destination?.lon ?? NaN, destination?.lat ?? NaN]
    const country = countryFootprint({ city: destination?.city || '', country: destination?.country || '', position })
    if (!hasMapCoordinates(position[1], position[0]) && !country?.polygons.length) continue
    const firstSeenMs = Math.min(...chunks.map(value => value.start_ms + (value.samples[0]?.[0] ?? 0)))
    const lastSeenMs = Math.max(...chunks.map(value => value.start_ms + (value.samples[value.samples.length - 1]?.[0] ?? 0) + value.bucket_ms))
    endpoints.push({ id, trackId: serviceKey(chunk), ip: chunk.destination_ip, label: chunk.service_label || destination?.ptr || chunk.destination_ip, provider: destination?.provider || '', city: destination?.city || '', country: destination?.country || '', position,
      availableFromMs: Math.max(firstSeenMs, destination?.observed_ms ?? Infinity), firstSeenMs,
      series: [{ id, startMs: firstSeenMs, endMs: lastSeenMs }] })
  }
  endpoints.sort((a,b) => a.firstSeenMs-b.firstSeenMs || a.id.localeCompare(b.id))
  return { sessionId: manifest?.id ?? null, sessionName: manifest?.name || 'InfraReveal session', startMs: manifest?.retained_from_ms ?? catalog.fromMs, endMs: manifest?.active ? manifest.server_ms : manifest?.ended_ms || catalog.toMs, origin, endpoints }
}
/** Selects only what can be known and shown at the current session time. */
export function projectMapFrame(scene: MapTimelineScene, cursorMs: number): MapFrame {
  const points: MapPoint[] = []
  const arcs: MapArc[] = []
  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > cursorMs || endpoint.firstSeenMs > cursorMs) continue
    const visible = endpoint.series.filter(series => series.startMs <= cursorMs)
    if (!visible.length) continue
    const country = countryFootprint(endpoint)
    const position = country?.position ?? endpoint.position
    if (!hasMapCoordinates(position[1], position[0])) continue
    points.push({
      id: endpoint.id, trackId: endpoint.trackId, ip: endpoint.ip, label: endpoint.label,
      provider: endpoint.provider, location: [endpoint.city, endpoint.country].filter(Boolean).join(', '),
      position, country, seriesCount: visible.length,
      activeSeriesCount: visible.filter(series => cursorMs <= series.endMs + ACTIVE_TRAIL_MS).length,
    })
    arcs.push({
      id: endpoint.id, trackId: endpoint.trackId, endpointId: endpoint.id,
      sourcePosition: [scene.origin.longitude, scene.origin.latitude], targetPosition: position, country,
    })
  }
  return { points, arcs }
}
