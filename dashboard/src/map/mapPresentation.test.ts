import { describe, expect, it } from 'vitest'
import type { MapArc } from './mapModel'
import { bundleMapArcs, connectionHasTrack } from './bundleMapArcs'
import { directionalVolumeArcs, trafficRadius, TRAFFIC_HISTORY_LENGTH } from './mapTraffic'
import type { TrafficProfile } from './mapTraffic'
import { countryFootprint } from './countryFootprints'

describe('map connection bundling', () => {
  const arc: MapArc = { id: 'a:1', endpointId: 'a', sourcePosition: [12, 57], targetPosition: [18, 59], activeSeriesCount: 2, bytes: 100, tilt: 5 }

  it('merges different tracks at the same locations and retains every contributor', () => {
    const result = bundleMapArcs([{ ...arc, trackId: 'news' }, { ...arc, id: 'b:1', endpointId: 'b', trackId: 'video', bytes: 200 }])
    expect(result).toHaveLength(1)
    expect(result[0]).toMatchObject({ endpointIds: ['a', 'b'], trackIds: ['news', 'video'], activeSeriesCount: 4, bytes: 300 })
    expect(connectionHasTrack(result[0], 'news')).toBe(true)
    expect(connectionHasTrack(result[0], 'video')).toBe(true)
    expect(connectionHasTrack(result[0], 'other')).toBe(false)
    expect(connectionHasTrack(result[0], null)).toBe(true)
    expect(arc.bytes).toBe(100)
  })

  it('keeps the shared arc in place when contributing tracks change', () => {
    const [before] = bundleMapArcs([{ ...arc, trackId: 'news' }])
    const [after] = bundleMapArcs([{ ...arc, trackId: 'video' }, { ...arc, id: 'b:1', endpointId: 'b', trackId: 'news' }])
    expect(after).toMatchObject({ id: before.id, height: before.height, tilt: before.tilt, sourcePosition: before.sourcePosition, targetPosition: before.targetPosition })
  })

  it('combines traffic rates before scaling the shared arc, independently in each direction', () => {
    const profile = (sent: number, received: number): TrafficProfile => ({
      source: 'sampled', rates: Array(TRAFFIC_HISTORY_LENGTH).fill(sent + received), packets: Array(TRAFFIC_HISTORY_LENGTH).fill(0),
      outRates: Array(TRAFFIC_HISTORY_LENGTH).fill(sent), inRates: Array(TRAFFIC_HISTORY_LENGTH).fill(received),
    })
    const connections = bundleMapArcs([{ ...arc, trackId: 'news' }, { ...arc, id: 'b:1', endpointId: 'b', trackId: 'video' }])
    const traffic = directionalVolumeArcs(connections, new Map([['a', profile(1_000, 4_000)], ['b', profile(2_000, 8_000)]]))
    expect(traffic).toHaveLength(2)
    expect(traffic[0]).toMatchObject({ id: connections[0].id, direction: 1, peakBytesPerSecond: 3_000, radii: Array(TRAFFIC_HISTORY_LENGTH).fill(trafficRadius(3_000)) })
    expect(traffic[1]).toMatchObject({ id: connections[0].id, direction: -1, peakBytesPerSecond: 12_000, radii: Array(TRAFFIC_HISTORY_LENGTH).fill(trafficRadius(12_000)) })
  })

  it('combines country estimates while preserving their geographic precision', () => {
    const country = countryFootprint({ country: 'Sweden', city: '', position: arc.targetPosition })!
    const connections = bundleMapArcs([
      { ...arc, country, trackId: 'news' }, { ...arc, country, id: 'b:1', endpointId: 'b', trackId: 'video' },
      { ...arc, id: 'c:1', endpointId: 'c', trackId: 'news' },
    ])
    expect(connections).toHaveLength(2)
    expect(connections[0]).toMatchObject({ country, endpointIds: ['a', 'b'], trackIds: ['news', 'video'] })
    expect(connections[1].country).toBeUndefined()
  })

  it('keeps distinct endpoints and reverse-direction connections separate', () => {
    const result = bundleMapArcs([arc, { ...arc, sourcePosition: [13, 58] }, { ...arc, sourcePosition: [18, 59], targetPosition: [12, 57] }])
    expect(result).toHaveLength(3)
  })
})
