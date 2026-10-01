import { describe, expect, it } from 'vitest'
import type { MapArc } from './mapModel'
import type { MapConnection } from './mapTracks'
import { createMapGeometryCache, sameTrafficArcGeometry, sameTrafficPathGeometry } from './mapGeometryCache'
import { trafficPathEdges } from './trafficPaths'
import { createWireWaveformCache } from './wireWaveform'
import { indexDestinationVolumes } from './destinationVolumes'
import { mapRenderQuality, parseMapPreferences } from './mapPreferences'

const route: MapArc = { id: 'a', endpointId: 'e', trackId: 't', routeId: 'r', sourcePosition: [12, 57], targetPosition: [-74, 41], gap: false, bytes: 100, activeFlowCount: 1, tilt: 0 }
describe('map work independent of the animation clock', () => {
  it('reuses geometry across counters, but invalidates a changed itinerary or quality', () => {
    const geometry = createMapGeometryCache()
    const first = geometry([route], 160)
    expect(geometry([{ ...route, bytes: 200, activeFlowCount: 0 }], 160)).toBe(first)
    const light = geometry([route], 48)
    expect(light.tracedPaths[0].samples.length).toBeLessThan(first.tracedPaths[0].samples.length)
    expect(light.tracedPaths[0].legs[0].path[0]).toEqual(first.tracedPaths[0].legs[0].path[0])
    expect(light.tracedPaths[0].legs[0].path.slice(-1)).toEqual(first.tracedPaths[0].legs[0].path.slice(-1))
    expect(geometry([{ ...route, targetPosition: [15, 50] }], 48)).not.toBe(light)
  })

  it('reuses a waveform across playhead totals and refreshes capture and connection coverage', () => {
    const waveform = createWireWaveformCache()
    const connection = { flow: { id: 'f' }, startMs: 1000, endMs: 6000, bytes: 10 } as MapConnection
    const index = indexDestinationVolumes([{ id: 'c', flow: 'f', session: 's', chunk_start: new Date(1000).toISOString(), chunk_ms: 5000, wire_bytes_in: 4000, wire_bytes_out: 1000, updated_at_source: new Date(6000).toISOString(), capture_complete: true, dropped_events: 0, updated: '' }])
    const range = { from: 1000, to: 6000 }
    const first = waveform([connection], index, range)
    expect(waveform([{ ...connection, bytes: 100 }], new Map(index), range)).toBe(first)
    expect(waveform([{ ...connection, endMs: 5000 }], index, range)).not.toBe(first)
    const revised = new Map(index)
    revised.set('f', { ...index.get('f')!, intervals: [] })
    expect(waveform([connection], revised, range)).not.toBe(first)
  })

  it('keeps geometry attributes for rate updates, but invalidates changed directions or paths', () => {
    const arc = { ...route, height: .1, endpointIds: ['e'], direction: 1, radii: Array(12).fill(1), peakBytesPerSecond: 10 }
    expect(sameTrafficArcGeometry([{ ...arc, radii: Array(12).fill(3) }], [arc])).toBe(true)
    expect(sameTrafficArcGeometry([{ ...arc, direction: -1 }], [arc])).toBe(false)
    expect(sameTrafficArcGeometry([{ ...arc, targetPosition: [15, 50] }], [arc])).toBe(false)
    const paths = createMapGeometryCache()([route], 48).tracedPaths
    const first = trafficPathEdges(paths.map(path => ({ ...path, radii: [1], direction: 1, peakBytesPerSecond: 1 })))
    const revised = trafficPathEdges(paths.map(path => ({ ...path, radii: [3], direction: 1, peakBytesPerSecond: 3 })))
    expect(sameTrafficPathGeometry(revised, first)).toBe(true)
    expect(sameTrafficPathGeometry(revised.map(edge => ({ ...edge, direction: -1 })), first)).toBe(false)
  })

  it('chooses lighter rendering on a four-core device while preserving an explicit preference', () => {
    expect(parseMapPreferences(null).quality).toBe('auto')
    expect(mapRenderQuality('auto', 4)).toEqual({ segments: 48, pixelRatio: 1 })
    expect(mapRenderQuality('full', 4).segments).toBe(160)
    expect(mapRenderQuality('raspberry-pi', 16).segments).toBe(48)
    expect(mapRenderQuality('auto', 16).segments).toBe(160)
  })
})
