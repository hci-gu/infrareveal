import type { MapArc } from './mapModel'

export type BundledMapArc = MapArc & { endpointIds: string[] }

/** Co-located IPs share a visual path while keeping each endpoint inspectable. */
export function bundleMapArcs(arcs: MapArc[]): BundledMapArc[] {
  const bundles = new Map<string, BundledMapArc>()
  for (const arc of arcs) {
    const key = `${arc.sourcePosition.join(',')}/${arc.targetPosition.join(',')}`
    const bundle = bundles.get(key)
    if (bundle) {
      bundle.activeFlowCount += arc.activeFlowCount
      bundle.bytes += arc.bytes
      if (!bundle.endpointIds.includes(arc.endpointId)) bundle.endpointIds.push(arc.endpointId)
    } else {
      bundles.set(key, { ...arc, id: key, tilt: 0, endpointIds: [arc.endpointId] })
    }
  }
  return Array.from(bundles.values())
}
