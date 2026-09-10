import { describe, expect, it } from 'vitest'
import type { MapArc, MapTimelineScene } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'
import { timelineActivity } from './timelineActivity'

describe('map route bundling', () => {
  const arc: MapArc = { id: 'a:1', endpointId: 'a', sourcePosition: [12, 57], targetPosition: [18, 59], activeFlowCount: 2, bytes: 100, tilt: 5 }

  it('merges co-located routes while retaining endpoint selection and volume', () => {
    const result = bundleMapArcs([arc, { ...arc, id: 'b:1', endpointId: 'b', bytes: 200 }])
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ endpointIds: ['a', 'b'], activeFlowCount: 4, bytes: 300 })
    expect(arc.bytes).toBe(100)
  })

  it('keeps distinct hops and reverse-direction segments separate', () => {
    const result = bundleMapArcs([arc, { ...arc, sourcePosition: [13, 58] }, { ...arc, sourcePosition: [18, 59], targetPosition: [12, 57] }])
    expect(result).toHaveLength(3)
  })
})

describe('map activity timeline', () => {
  function scene(intervals: [number, number][]): MapTimelineScene {
    return {
      sessionId: 'session', sessionName: 'Recorded', startMs: 1000, endMs: 5000,
      origin: { longitude: 12, latitude: 57, label: 'Gateway' }, totalFlowCount: intervals.length,
      endpoints: [{ id: 'a', ip: '192.0.2.1', label: 'Endpoint', provider: '', city: '', country: '', position: [18, 59], availableFromMs: 1000, firstSeenMs: 1000, lastSeenMs: 5000, routes: [],
        flows: intervals.map(([startMs, endMs], i) => ({ id: String(i), startMs, endMs, bytes: 100, packets: 1 })),
      }],
    }
  }

  it('shows overlapping flows, including traffic spanning the visible range', () => {
    expect(timelineActivity(scene([[0, 6000], [2100, 2900], [3200, 4200]]), 5000, 4)).toEqual([1, 2, 2, 2])
  })

  it('excludes flows outside the range and handles an instantaneous flow', () => {
    expect(timelineActivity(scene([[0, 500], [6000, 8000], [2100, 2100]]), 5000, 4)).toEqual([0, 1, 0, 0])
  })

  it('keeps empty and zero-duration timelines finite', () => {
    expect(timelineActivity(scene([]), 1000, 4)).toEqual([0, 0, 0, 0])
    expect(timelineActivity(scene([]), 5000, 0)).toEqual([])
  })
})
