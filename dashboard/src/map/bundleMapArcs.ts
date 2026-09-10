import type { MapArc } from './mapModel'

export type BundledMapArc = MapArc & { endpointIds: string[]; height: number }

/** Only co-located IPs in the same track share a path and its measured volume. */
export function bundleMapArcs(arcs: MapArc[]): BundledMapArc[] {
  const bundles = new Map<string, BundledMapArc>()
  for (const arc of arcs) {
    const key = `${arc.trackId ?? ''}/${arc.sourcePosition.join(',')}/${arc.targetPosition.join(',')}/${Boolean(arc.routeId)}/${Boolean(arc.gap)}/${(arc.progressStart ?? 0).toFixed(6)}/${(arc.progressEnd ?? 1).toFixed(6)}`
    const bundle = bundles.get(key)
    if (bundle) {
      bundle.activeFlowCount += arc.activeFlowCount
      bundle.bytes += arc.bytes
      if (!bundle.endpointIds.includes(arc.endpointId)) bundle.endpointIds.push(arc.endpointId)
    } else {
      bundles.set(key, { ...arc, id: key, tilt: 0, height: arc.routeId ? 0.09 : 0.18, endpointIds: [arc.endpointId] })
    }
  }
  const paths = new Map<string, BundledMapArc[]>()
  for (const arc of bundles.values()) {
    const path = `${arc.sourcePosition.join(',')}/${arc.targetPosition.join(',')}`
    const siblings = paths.get(path) ?? []
    siblings.push(arc)
    paths.set(path, siblings)
  }
  // Separate activities sharing a CDN location without inventing geographic offsets.
  for (const siblings of paths.values()) {
    const tracks = [...new Set(siblings.map(arc => arc.trackId ?? ''))].sort()
    if (tracks.length > 1) siblings.forEach(arc => { arc.height = (arc.routeId ? 0.06 : 0.13) + tracks.indexOf(arc.trackId ?? '') / (tracks.length - 1) * 0.15 })
  }
  return Array.from(bundles.values())
}
