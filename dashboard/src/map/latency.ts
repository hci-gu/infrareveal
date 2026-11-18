import type { TrafficChunk } from '@infrareveal/session-state'
import type { GatewayOrigin, MapPosition } from './mapModel'

/**
 * Passive round-trip times (measured at the gateway from connection
 * handshakes, see pocketbase/observer/rtt.go) and what physics says about them.
 */
export type RoundTrip = { ms: number; source: 'tcp' | 'udp' }

/** TCP handshakes outrank UDP first-reply upper bounds; within a source the lowest wins. */
export function mergeRoundTrip(current: RoundTrip | undefined, next: RoundTrip | undefined): RoundTrip | undefined {
  if (!next) return current
  if (!current || (next.source === 'tcp' && current.source !== 'tcp') || (next.source === current.source && next.ms < current.ms)) return next
  return current
}

/** Lowest round trip among chunks starting within [fromMs, toMs]. */
export function windowRoundTrip(chunks: readonly TrafficChunk[], fromMs: number, toMs: number): RoundTrip | undefined {
  let best: RoundTrip | undefined
  for (const chunk of chunks) {
    if (!chunk.rtt_us || !chunk.rtt_source || chunk.start_ms + chunk.chunk_ms <= fromMs || chunk.start_ms > toMs) continue
    best = mergeRoundTrip(best, { ms: chunk.rtt_us / 1000, source: chunk.rtt_source })
  }
  return best
}

export function distanceKm([lon1, lat1]: MapPosition, [lon2, lat2]: MapPosition) {
  const rad = Math.PI / 180, dLat = (lat2 - lat1) * rad, dLon = (lon2 - lon1) * rad
  const h = Math.sin(dLat / 2) ** 2 + Math.cos(lat1 * rad) * Math.cos(lat2 * rad) * Math.sin(dLon / 2) ** 2
  return 12_742 * Math.asin(Math.min(1, Math.sqrt(h)))
}

/** Light in fibre covers ~200 km per millisecond one way, so ~100 km per millisecond of round trip. */
export const FIBRE_KM_PER_RTT_MS = 100
/** Measurements below this share of the physical floor cannot come from the claimed location. */
export const CONTRADICTION_MARGIN = 0.8

/** The fastest round trip physics allows between the gateway and a position (straight fibre, no queueing). */
export function fibreFloorMs(origin: GatewayOrigin, position: MapPosition) {
  return distanceKm([origin.longitude, origin.latitude], position) / FIBRE_KM_PER_RTT_MS
}

export type Placement = 'contradicted' | 'consistent'
/**
 * `contradicted`: answered faster than light allows from its IP location, so it
 * was served from somewhere closer (anycast, CDN edge, wrong geolocation).
 */
export function placement(rttMs: number, floorMs: number): Placement {
  return rttMs < floorMs * CONTRADICTION_MARGIN ? 'contradicted' : 'consistent'
}

/** The farthest a reply could have come from, given its round trip (straight fibre). */
export const reachKm = (rttMs: number) => rttMs * FIBRE_KM_PER_RTT_MS

/** Initial great-circle bearing from the gateway, degrees clockwise from north. */
export function bearingDegrees(origin: GatewayOrigin, [lon, lat]: MapPosition) {
  const rad = Math.PI / 180, φ1 = origin.latitude * rad, φ2 = lat * rad, Δλ = (lon - origin.longitude) * rad
  const y = Math.sin(Δλ) * Math.cos(φ2), x = Math.cos(φ1) * Math.sin(φ2) - Math.sin(φ1) * Math.cos(φ2) * Math.cos(Δλ)
  return (Math.atan2(y, x) / rad + 360) % 360
}

/** Rings drawn in the latency view, in milliseconds. */
export const LATENCY_RINGS = [10, 25, 50, 100, 200]
/** Destinations without a measurement sit on a ring beyond the last one. */
export const UNMEASURED_RING_MS = 320

/**
 * Latency layout geometry. A square-root radius separates 1–20 ms neighbours
 * while still fitting 300 ms intercontinental round trips. The planar layout is
 * handed to the Web Mercator view as substitute coordinates around (0°, 0°):
 * x becomes longitude and y is inverted through Mercator, so rings stay round.
 */
const DEGREES_PER_SQRT_MS = 2.6
export function latencyPlane(rttMs: number, bearing: number): [number, number] {
  const radius = Math.sqrt(Math.max(0, rttMs)) * DEGREES_PER_SQRT_MS
  const angle = bearing * Math.PI / 180
  return [radius * Math.sin(angle), radius * Math.cos(angle)]
}
export function planeToMap([x, y]: [number, number]): MapPosition {
  const yRadians = y * Math.PI / 180
  return [x, (2 * Math.atan(Math.exp(yRadians)) - Math.PI / 2) * 180 / Math.PI]
}
export const latencyPosition = (rttMs: number, bearing: number) => planeToMap(latencyPlane(rttMs, bearing))
export function latencyRing(rttMs: number, steps = 128): MapPosition[] {
  return Array.from({ length: steps + 1 }, (_, i) => latencyPosition(rttMs, i / steps * 360))
}

export type LatencyBand = { id: string; label: string; maxMs: number }
export const LATENCY_BANDS: LatencyBand[] = [
  { id: 'local', label: 'Under 10 ms', maxMs: 10 },
  { id: 'regional', label: '10–50 ms', maxMs: 50 },
  { id: 'continental', label: '50–150 ms', maxMs: 150 },
  { id: 'intercontinental', label: 'Over 150 ms', maxMs: Infinity },
]
export const latencyBand = (rttMs: number) => LATENCY_BANDS.find(band => rttMs < band.maxMs)!

export const formatRtt = (ms: number) => ms < 10 ? `${ms.toFixed(1)} ms` : `${Math.round(ms)} ms`

export type LatencySummary = {
  /** Bytes per band id, plus `unmeasured`. */
  bands: Record<string, number>
  total: number
  /** Bytes whose round trip rules out their IP location. */
  contradicted: number
  /** Bytes with a measurement and a known location (the base for `contradicted`). */
  locatedMeasured: number
}
/** Byte-weighted round-trip bands for the filtered workspace. */
export function summarizeLatency(locations: readonly { bytes: number; rttMs?: number; position?: MapPosition }[], origin: GatewayOrigin): LatencySummary {
  const bands: Record<string, number> = Object.fromEntries([...LATENCY_BANDS.map(band => [band.id, 0]), ['unmeasured', 0]])
  let total = 0, contradicted = 0, locatedMeasured = 0
  for (const location of locations) {
    if (location.bytes <= 0) continue
    total += location.bytes
    if (location.rttMs === undefined) { bands.unmeasured += location.bytes; continue }
    bands[latencyBand(location.rttMs).id] += location.bytes
    if (!location.position) continue
    locatedMeasured += location.bytes
    if (placement(location.rttMs, fibreFloorMs(origin, location.position)) === 'contradicted') contradicted += location.bytes
  }
  return { bands, total, contradicted, locatedMeasured }
}
