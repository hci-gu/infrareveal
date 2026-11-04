import { describe, expect, it } from 'vitest'
import type { MapArc } from './mapModel'
import type { MapSeries } from './mapTracks'
import { createMapGeometryCache, sameTrafficArcGeometry } from './mapGeometryCache'
import { createWireWaveformCache } from './wireWaveform'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { seriesKey, type TrafficChunk } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import { mapRenderQuality, parseMapPreferences } from './mapPreferences'

const connection: MapArc = { id: 'a', endpointId: 'e', trackId: 't', sourcePosition: [12, 57], targetPosition: [-74, 41], bytes: 100, activeSeriesCount: 1, tilt: 0 }
describe('map work independent of the animation clock', () => {
  it('reuses geometry across counters, but invalidates changed destinations', () => {
    const geometry = createMapGeometryCache()
    const first = geometry([connection])
    expect(first.connections).toHaveLength(1)
    expect(geometry([{ ...connection, bytes: 200, activeSeriesCount: 0 }])).toBe(first)
    expect(geometry([{ ...connection, targetPosition: [15, 50] }])).not.toBe(first)
    const changedTrack = geometry([{ ...connection, trackId: 'another-track' }])
    expect(changedTrack.connections[0].trackIds).toEqual(['another-track'])
    expect(changedTrack.connections[0].id).toBe(first.connections[0].id)
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
    const arc = { ...connection, height: .1, endpointIds: ['e'], trackIds: ['t'], direction: 1, radii: Array(12).fill(1), peakBytesPerSecond: 10 }
    expect(sameTrafficArcGeometry([{ ...arc, radii: Array(12).fill(3) }], [arc])).toBe(true)
    expect(sameTrafficArcGeometry([{ ...arc, direction: -1 }], [arc])).toBe(false)
    expect(sameTrafficArcGeometry([{ ...arc, targetPosition: [15, 50] }], [arc])).toBe(false)
    expect(sameTrafficArcGeometry([{ ...arc, trackIds: ['another-track'] }], [arc])).toBe(false)
  })

  it('chooses lighter rendering on a four-core device while preserving an explicit preference', () => {
    expect(parseMapPreferences(null).quality).toBe('auto')
    expect(mapRenderQuality('auto', 4)).toMatchObject({ light: true, segments: 32, pixelRatio: 1, dataIntervalMs: 1000 })
    expect(mapRenderQuality('full', 4).segments).toBe(160)
    expect(mapRenderQuality('raspberry-pi', 16).segments).toBe(32)
    expect(mapRenderQuality('auto', 16).segments).toBe(160)
  })
})
