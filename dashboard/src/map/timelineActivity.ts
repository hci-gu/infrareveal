import type { MapTimelineScene } from './mapModel'

/** Counts overlapping geolocated flows, rather than inventing packet throughput. */
export function timelineActivity(scene: MapTimelineScene, endMs: number, binCount = 96): number[] {
  if (binCount <= 0) return []
  const changes = new Array<number>(binCount + 1).fill(0)
  const duration = Math.max(1, endMs - scene.startMs)
  for (const endpoint of scene.endpoints) {
    for (const flow of endpoint.flows) {
      if (flow.startMs > endMs || flow.endMs < scene.startMs) continue
      const start = Math.min(binCount - 1, Math.max(0, Math.floor((flow.startMs - scene.startMs) / duration * binCount)))
      const end = Math.min(binCount - 1, Math.max(start, Math.floor((flow.endMs - scene.startMs) / duration * binCount)))
      changes[start] += 1
      changes[end + 1] -= 1
    }
  }
  let count = 0
  return changes.slice(0, binCount).map((change) => (count += change))
}
