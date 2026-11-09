import type { MapArc } from './mapModel'

export type BundledMapArc = Omit<MapArc, 'trackId' | 'endpointId'> & { endpointIds: string[]; trackIds: string[] }

/** All traffic between the same locations shares one arc and its measured volume. */
export function bundleMapArcs(arcs: MapArc[]): BundledMapArc[] {
  const bundles = new Map<string, BundledMapArc>()
  for (const arc of arcs) {
    const key = `${arc.sourcePosition.join(',')}/${arc.targetPosition.join(',')}/${arc.country?.code ?? ''}`
    const bundle = bundles.get(key)
    if (bundle) {
      if (!bundle.endpointIds.includes(arc.endpointId)) bundle.endpointIds.push(arc.endpointId)
      if (arc.trackId && !bundle.trackIds.includes(arc.trackId)) bundle.trackIds.push(arc.trackId)
    } else {
      bundles.set(key, {
        id: key, sourcePosition: arc.sourcePosition, targetPosition: arc.targetPosition, country: arc.country,
        endpointIds: [arc.endpointId], trackIds: arc.trackId ? [arc.trackId] : [],
      })
    }
  }
  return Array.from(bundles.values())
}

export function connectionHasTrack(arc: BundledMapArc, selectedTrack: string | null): boolean {
  return selectedTrack === null || arc.trackIds.includes(selectedTrack)
}
