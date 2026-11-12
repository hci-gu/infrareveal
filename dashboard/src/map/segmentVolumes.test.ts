import { describe, expect, it } from 'vitest'
import type { MapWindow, TrafficChunk } from '@infrareveal/session-state'
import { seriesKey } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { createDestinationVolumeCache, indexDestinationVolumes, seriesLastActivity, seriesVolume } from './destinationVolumes'
import type { MapSeries } from './mapTracks'
import { wireWaveform } from './wireWaveform'

const part = (from: number, multiplier = 1): MapWindow => ({ ...fixture.window, from_ms: from, to_ms: from + 30000,
  coverage: [{ ...fixture.window.coverage[0], start_ms: from, end_ms: from + 30000, quality: 'complete' }],
  series: [{ ...fixture.window.series[0], start_ms: from, samples: [[0, 10 * multiplier, 20 * multiplier, 5, 15, 1, 1], [1000, 30 * multiplier, 40 * multiplier, 5, 15, 1, 1]] } as TrafficChunk],
}) as MapWindow
const combine = (parts: MapWindow[], floor = parts[0].from_ms): MapWindow => ({ ...parts[0], from_ms: floor, to_ms: parts[parts.length - 1].to_ms, segments: parts, series: parts.flatMap(p => p.series), coverage: parts.flatMap(p => p.coverage) })

describe('segment prefix indexes', () => {
  it('matches raw totals, last activity and waveform bins at every boundary', () => {
    const data = combine([part(100000), part(130000), part(160000)])
    const cached = createDestinationVolumeCache()(data)
    const flat = indexDestinationVolumes(data.series, data.from_ms, data.coverage, data.to_ms)
    const series = { id: seriesKey(data.series[0]), startMs: 100000, endMs: 190000 } as MapSeries
    for (const cursor of [100000, 100049, 100050, 101025, 101050, 129999, 130000, 130049, 130050, 160000, 161050, 190000]) {
      for (const from of [100000, 100025, 100050, 129000, 130000, 160000].filter(from => from <= cursor)) {
        expect(seriesVolume(series, cached, cursor, from)).toEqual(seriesVolume(series, flat, cursor, from))
      }
      expect(seriesLastActivity(series, cached, cursor)).toBe(seriesLastActivity(series, flat, cursor))
    }
    expect(wireWaveform([series], cached, { from: 100025, to: 180000 }, 96)).toEqual(wireWaveform([series], flat, { from: 100025, to: 180000 }, 96))
  })
  it('reuses immutable indexes while replacing corrected tail and clipping retention', () => {
    const loader = createDestinationVolumeCache(), first = part(100000), second = part(130000)
    const key = seriesKey(first.series[0]), before = loader(combine([first, second]))
    const changed = combine([first, part(130000, 3)])
    const after = loader(changed)
    expect(after.get(key)!.parts![0].value).toBe(before.get(key)!.parts![0].value)
    expect(after.get(key)!.parts![1].value).not.toBe(before.get(key)!.parts![1].value)
    const series = { id: key, startMs: 100000, endMs: 160000 } as MapSeries
    expect(seriesVolume(series, after, 160000)).toMatchObject({ sent: 160, received: 240 })
    const retained = loader({ ...changed, from_ms: 130025 })
    expect(seriesVolume(series, retained, 160000)).toMatchObject({ sent: 90, received: 120 })
  })
})
