import type { MapArc } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'
import { buildTrafficPaths, trafficPathStrips } from './trafficPaths'
import type { TrafficPathEdge } from './trafficPaths'
import type { TrafficArc } from './mapTraffic'

/** Radii have their own update triggers; unchanged positions keep their GPU buffers. */
export function sameTrafficArcGeometry(data: unknown, oldData?: unknown) {
  if (!Array.isArray(data) || !Array.isArray(oldData)) return false
  const next = data as TrafficArc[], previous = oldData as TrafficArc[]
  return next.length === previous.length && next.every((arc, i) => {
    const old = previous[i]
    return arc.id === old.id && arc.trackId === old.trackId && arc.direction === old.direction
      && arc.sourcePosition === old.sourcePosition && arc.targetPosition === old.targetPosition
      && arc.height === old.height && arc.tilt === old.tilt && arc.progressStart === old.progressStart && arc.progressEnd === old.progressEnd
  })
}

export function sameTrafficPathGeometry(data: unknown, oldData?: unknown) {
  if (!Array.isArray(data) || !Array.isArray(oldData)) return false
  const next = data as TrafficPathEdge[], previous = oldData as TrafficPathEdge[]
  return next.length === previous.length && next.every((edge, i) => {
    const old = previous[i]
    return edge.trackId === old.trackId && edge.direction === old.direction && edge.sourcePosition === old.sourcePosition
      && edge.targetPosition === old.targetPosition && edge.previousPosition === old.previousPosition && edge.nextPosition === old.nextPosition
      && edge.progress[0] === old.progress[0] && edge.progress[1] === old.progress[1]
  })
}

/** Only topology owns geometry. Counters and active status are projected separately. */
export function createMapGeometryCache() {
  let previousKey = ''
  let previous: ReturnType<typeof build> | undefined
  function build(arcs: MapArc[], segments: number) {
    const tracedPaths = buildTrafficPaths(arcs.filter(arc => !arc.country), segments)
    return {
      routes: bundleMapArcs(arcs.filter(arc => !arc.routeId && !arc.country)),
      countryRoutes: bundleMapArcs(arcs.filter(arc => arc.country)),
      tracedPaths, tracedStrips: trafficPathStrips(tracedPaths),
    }
  }
  return (arcs: MapArc[], segments: number) => {
    const ordered = [...arcs].sort((a, b) => a.id.localeCompare(b.id))
    const key = JSON.stringify([segments, ordered.map(arc => [arc.id, arc.endpointId, arc.trackId, arc.routeId, arc.sourcePosition, arc.targetPosition, arc.gap, arc.progressStart, arc.progressEnd, arc.country?.code])])
    if (key !== previousKey || !previous) { previous = build(ordered, segments); previousKey = key }
    return previous
  }
}
