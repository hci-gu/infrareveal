import type { MapArc, MapPosition } from './mapModel'

export type PathPosition = [longitude: number, latitude: number, altitude: number]
type PathSample = { position: PathPosition; progress: number }
export type TrafficPath = {
  id: string
  trackId?: string
  endpointIds: string[]
  positions: MapPosition[]
  gaps: boolean[]
  samples: PathSample[]
  legs: { path: PathPosition[]; gap: boolean }[]
}
export type PathVolume = { direction?: number; radii: number[]; peakBytesPerSecond: number }
export type TrafficPathEdge = PathVolume & {
  trackId?: string
  sourcePosition: PathPosition
  targetPosition: PathPosition
  previousPosition: PathPosition
  nextPosition: PathPosition
  progress: [number, number]
}
export type TrafficPathStrip = { trackId?: string; path: PathPosition[] }

export function trafficPathStrips(paths: TrafficPath[]): TrafficPathStrip[] {
  return paths.flatMap(route => route.legs.flatMap(leg => {
    if (!leg.gap) return [{ trackId: route.trackId, path: leg.path }]
    const strips: TrafficPathStrip[] = []
    for (let i = 0; i < leg.path.length - 1; i += 4) strips.push({ trackId: route.trackId, path: leg.path.slice(i, i + 3) })
    return strips
  }))
}

/** Bundle entire itineraries. A shared router does not create another origin-to-destination stream. */
export function buildTrafficPaths(arcs: MapArc[]): TrafficPath[] {
  const itineraries = new Map<string, MapArc[]>()
  for (const arc of arcs) {
    if (!arc.routeId) continue
    const key = `${arc.endpointId}/${arc.routeId}`
    const legs = itineraries.get(key) ?? []
    legs.push(arc)
    itineraries.set(key, legs)
  }
  const paths = new Map<string, TrafficPath>()
  for (const legs of itineraries.values()) {
    legs.sort((a, b) => (a.progressStart ?? 0) - (b.progressStart ?? 0))
    const positions = [legs[0].sourcePosition, ...legs.map(leg => leg.targetPosition)]
    const gaps = legs.map(leg => Boolean(leg.gap))
    const id = JSON.stringify([legs[0].trackId, positions, gaps])
    const existing = paths.get(id)
    if (existing) existing.endpointIds.push(legs[0].endpointId)
    else paths.set(id, { id, trackId: legs[0].trackId, endpointIds: [legs[0].endpointId], positions, gaps, samples: [], legs: [] })
  }
  const siblings = new Map<string, TrafficPath[]>()
  for (const path of paths.values()) {
    const key = JSON.stringify(path.positions)
    const group = siblings.get(key) ?? []
    group.push(path)
    siblings.set(key, group)
  }
  for (const group of siblings.values()) {
    const tracks = [...new Set(group.map(path => path.trackId ?? ''))].sort()
    for (const path of group) {
      const height = 0.045 + (tracks.length > 1 ? tracks.indexOf(path.trackId ?? '') / (tracks.length - 1) * 0.07 : 0)
      Object.assign(path, sampleTrafficPath(path.positions, path.gaps, height))
    }
  }
  return [...paths.values()]
}

/** The strip and the tube use these exact same vertices, including every router in sequence. */
export function sampleTrafficPath(positions: MapPosition[], gaps: boolean[], height = 0.045) {
  const samples: PathSample[] = []
  const legs: TrafficPath['legs'] = []
  const count = positions.length - 1
  for (let leg = 0; leg < count; leg++) {
    const source = positions[leg], target = positions[leg + 1]
    const a = sphere(source), b = sphere(target)
    const angle = Math.acos(Math.max(-1, Math.min(1, a.reduce((sum, value, i) => sum + value * b[i], 0))))
    const steps = Math.max(12, Math.ceil(160 / count), Math.ceil(angle * 180 / Math.PI))
    const path: PathPosition[] = []
    for (let step = 0; step <= steps; step++) {
      const t = step / steps
      const location = step === 0 ? source : step === steps ? target : greatCircle(source, target, a, b, angle, t)
      // Zero slope at routers gives the tube a clean, shared join on the map surface.
      const position: PathPosition = [location[0], location[1], Math.sin(Math.PI * t) ** 2 * angle * 6_371_000 * height]
      if (step === 0 || step === steps) position[2] = 0
      path.push(position)
      // Equal time per leg makes short local hops perceptible before the long-haul segment.
      if (leg === 0 || step > 0) samples.push({ position, progress: (leg + t) / count })
    }
    legs.push({ path, gap: gaps[leg] ?? true })
  }
  return { samples, legs }
}

/** Adjacent edges share both a ring and its orientation, so the volume never pinches off at a hop. */
export function trafficPathEdges(paths: (TrafficPath & PathVolume)[]): TrafficPathEdge[] {
  return paths.flatMap(path => path.samples.slice(1).map((sample, i) => ({
    direction: path.direction, trackId: path.trackId, radii: path.radii, peakBytesPerSecond: path.peakBytesPerSecond,
    sourcePosition: path.samples[i].position, targetPosition: sample.position,
    previousPosition: path.samples[Math.max(0, i - 1)].position,
    nextPosition: path.samples[Math.min(path.samples.length - 1, i + 2)].position,
    progress: [path.samples[i].progress, sample.progress] as [number, number],
  })))
}

function sphere([lon, lat]: MapPosition) {
  const x = lon * Math.PI / 180, y = lat * Math.PI / 180
  return [Math.cos(y) * Math.cos(x), Math.cos(y) * Math.sin(x), Math.sin(y)]
}

function greatCircle(source: MapPosition, target: MapPosition, a: number[], b: number[], angle: number, t: number): MapPosition {
  if (angle < 0.00001 || Math.abs(angle - Math.PI) < 0.001) {
    const delta = ((target[0] - source[0] + 540) % 360) - 180
    return [((source[0] + delta * t + 540) % 360) - 180, source[1] + (target[1] - source[1]) * t]
  }
  const p = a.map((value, i) => value * Math.sin((1 - t) * angle) + b[i] * Math.sin(t * angle))
  return [Math.atan2(p[1], p[0]) * 180 / Math.PI, Math.atan2(p[2], Math.hypot(p[0], p[1])) * 180 / Math.PI]
}
