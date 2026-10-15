import { describe, expect, it } from 'vitest'
import type { MapArc } from './mapModel'
import type { MapSeries } from './mapTracks'
import { createMapGeometryCache, sameTrafficArcGeometry, sameTrafficPathGeometry } from './mapGeometryCache'
import { trafficPathEdges } from './trafficPaths'
import { createWireWaveformCache } from './wireWaveform'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { seriesKey, type TrafficChunk } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import { mapRenderQuality, parseMapPreferences } from './mapPreferences'

const route: MapArc = { id: 'a', endpointId: 'e', trackId: 't', routeId: 'r', sourcePosition: [12, 57], targetPosition: [-74, 41], gap: false, bytes: 100, activeSeriesCount: 1, tilt: 0 }
describe('map work independent of the animation clock', () => {
  it('reuses geometry across counters, but invalidates a changed itinerary or quality', () => {
    const geometry = createMapGeometryCache()
    const first = geometry([route], 160)
    expect(geometry([{ ...route, bytes: 200, activeSeriesCount: 0 }], 160)).toBe(first)
    const light = geometry([route], 48)
    expect(light.tracedPaths[0].samples.length).toBeLessThan(first.tracedPaths[0].samples.length)
    expect(light.tracedPaths[0].legs[0].path[0]).toEqual(first.tracedPaths[0].legs[0].path[0])
    expect(light.tracedPaths[0].legs[0].path.slice(-1)).toEqual(first.tracedPaths[0].legs[0].path.slice(-1))
    expect(geometry([{ ...route, targetPosition: [15, 50] }], 48)).not.toBe(light)
  })

  it('reuses a waveform across playhead totals and refreshes capture and connection coverage', () => {
    const waveform = createWireWaveformCache()
    const chunk = fixture.window.series[0] as TrafficChunk
    const id = seriesKey(chunk)
    const connection = { id, startMs: chunk.start_ms, endMs: chunk.start_ms + 100, bytes: 10 } as MapSeries
    const index = indexDestinationVolumes([chunk], chunk.start_ms, fixture.window.coverage)
    const range = { from: chunk.start_ms, to: chunk.start_ms+100 }
    const first = waveform([connection], index, range)
    expect(waveform([{ ...connection, bytes: 100 }], Object.assign(new Map(index), { fromMs: index.fromMs, coverage: index.coverage }), range)).toBe(first)
    expect(waveform([{ ...connection, endMs: 5000 }], index, range)).not.toBe(first)
    const revised = new Map(index)
    revised.set(id, { ...index.get(id)!, intervals: [] })
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
    expect(mapRenderQuality('auto', 4)).toMatchObject({ light: true, segments: 32, pixelRatio: 1, dataIntervalMs: 1000 })
    expect(mapRenderQuality('full', 4).segments).toBe(160)
    expect(mapRenderQuality('raspberry-pi', 16).segments).toBe(32)
    expect(mapRenderQuality('auto', 16).segments).toBe(160)
  })
})
