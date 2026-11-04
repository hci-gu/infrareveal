import type { MapArc } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'
import type { TrafficArc } from './mapTraffic'

/** Radii have their own update triggers; unchanged positions keep their GPU buffers. */
export function sameTrafficArcGeometry(data: unknown, oldData?: unknown) {
  if (!Array.isArray(data) || !Array.isArray(oldData)) return false
  const next = data as TrafficArc[], previous = oldData as TrafficArc[]
  return next.length === previous.length && next.every((arc, i) => {
    const old = previous[i]
    return arc.id === old.id && arc.trackIds === old.trackIds && arc.direction === old.direction
      && arc.sourcePosition === old.sourcePosition && arc.targetPosition === old.targetPosition
      && arc.height === old.height && arc.tilt === old.tilt
  })
}

/** Only topology owns geometry. Counters and active status are projected separately. */
export function createMapGeometryCache() {
  let previousKey = ''
  let previous: ReturnType<typeof build> | undefined
  function build(arcs: MapArc[]) {
    return {
      connections: bundleMapArcs(arcs.filter(arc => !arc.country)),
      countryConnections: bundleMapArcs(arcs.filter(arc => arc.country)),
    }
  }
  return (arcs: MapArc[]) => {
    const ordered = [...arcs].sort((a, b) => a.id.localeCompare(b.id))
    const key = JSON.stringify(ordered.map(arc => [arc.id, arc.endpointId, arc.trackId, arc.sourcePosition, arc.targetPosition, arc.country?.code]))
    if (key !== previousKey || !previous) { previous = build(ordered); previousKey = key }
    return previous
  }
}
