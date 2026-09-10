import { describe, expect, it } from 'vitest'
import type { MapArc, MapPosition } from './mapModel'
import { buildTrafficPaths, sampleTrafficPath, trafficPathEdges } from './trafficPaths'
import { volumeArcs } from './mapTraffic'

const positions: MapPosition[] = [[12, 57], [10, 55], [2, 49], [-74, 41]]
function itinerary(endpointId = 'a', trackId = 'site'): MapArc[] {
  return positions.slice(1).map((targetPosition, i) => ({ id: `${endpointId}:${i}`, endpointId, trackId, routeId: 'route', sourcePosition: positions[i], targetPosition, activeFlowCount: 1, bytes: 1000, tilt: 0, progressStart: i / 3, progressEnd: (i + 1) / 3, gap: i === 1 }))
}

describe('traffic following an entire traceroute', () => {
  it('forms one itinerary in hop order with no direct bypass', () => {
    const paths = buildTrafficPaths(itinerary().reverse())
    expect(paths).toHaveLength(1)
    expect(paths[0].positions).toEqual(positions)
    expect(paths[0].legs).toHaveLength(3)
    for (const [i, leg] of paths[0].legs.entries()) {
      expect(leg.path[0].slice(0, 2)).toEqual(positions[i])
      expect(leg.path[leg.path.length - 1].slice(0, 2)).toEqual(positions[i + 1])
    }
    expect(buildTrafficPaths([{ ...itinerary()[0], routeId: undefined }])).toEqual([])
  })

  it('shares the same position, progress, and neighboring rings at every hop join', () => {
    const paths = buildTrafficPaths(itinerary())
    const edges = trafficPathEdges(paths.map(path => ({ ...path, radii: Array(12).fill(8), peakBytesPerSecond: 1000 })))
    for (let i = 1; i < edges.length; i++) {
      const before = edges[i - 1], after = edges[i]
      expect(before.targetPosition).toEqual(after.sourcePosition)
      expect(before.progress[1]).toBe(after.progress[0])
      expect(before.sourcePosition).toEqual(after.previousPosition)
      expect(before.nextPosition).toEqual(after.targetPosition)
    }
    for (const hop of positions.slice(1, -1)) {
      const incoming = edges.find(edge => edge.targetPosition[0] === hop[0] && edge.targetPosition[1] === hop[1])!
      expect(incoming.targetPosition[2]).toBe(0)
      expect(incoming.progress[1]).toBeGreaterThan(0)
      expect(incoming.progress[1]).toBeLessThan(1)
    }
  })

  it('allocates visible travel time to a short router hop before the long-haul leg', () => {
    const result = sampleTrafficPath([[12, 57], [12.01, 57.01], [-74, 41]], [false, false])
    const router = result.samples.find(sample => sample.position[0] === 12.01 && sample.position[1] === 57.01)!
    expect(router.progress).toBe(.5)
    expect(result.samples[0].progress).toBe(0)
    expect(result.samples[result.samples.length - 1].progress).toBe(1)
  })

  it('sums a shared itinerary once and keeps a different hop sequence or track separate', () => {
    const detour = itinerary('c').map(arc => ({ ...arc, sourcePosition: arc.sourcePosition === positions[1] ? [15, 53] as MapPosition : arc.sourcePosition, targetPosition: arc.targetPosition === positions[1] ? [15, 53] as MapPosition : arc.targetPosition }))
    const paths = buildTrafficPaths([...itinerary('a'), ...itinerary('b'), ...detour, ...itinerary('d', 'another-site')])
    expect(paths).toHaveLength(3)
    const volumes = volumeArcs(paths, new Map(['a', 'b', 'c', 'd'].map(id => [id, { rates: Array(12).fill(1000), packets: Array(12).fill(1), source: 'sampled' as const }])))
    expect(volumes.map(path => path.peakBytesPerSecond).sort((a, b) => a - b)).toEqual([1000, 1000, 2000])
    expect(volumes[0].endpointIds).toEqual(['a', 'b'])
  })

  it('samples dateline crossings and degenerate positions without NaNs or a world-spanning shortcut', () => {
    const crossing = sampleTrafficPath([[179, 0], [-179, 0], [-175, 2]], [false, true])
    expect(crossing.samples.every(sample => Math.abs(sample.position[0]) >= 175)).toBe(true)
    for (const route of [crossing, sampleTrafficPath([[12, 57], [12, 57]], [true]), sampleTrafficPath([[0, 0], [180, 0]], [false])]) {
      expect(route.samples.every(sample => sample.position.every(Number.isFinite) && Number.isFinite(sample.progress))).toBe(true)
    }
  })
})
