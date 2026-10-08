import { describe, expect, it } from 'vitest'
import type { MapArc } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'

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
