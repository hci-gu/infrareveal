import { describe, expect, it } from 'vitest'
import { seriesKey, type TrafficChunk } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { indexDestinationVolumes } from './destinationVolumes'
import type { MapSeries } from './mapTracks'
import { waveformCeiling, waveformGrid, wireWaveform } from './wireWaveform'

const bins = (received: number, sent = 0) => [[{ received, sent, complete: true, observed: true }]]

describe('steady timeline waveforms', () => {
  it('holds the observed scale when a burst expires or becomes quieter', () => {
    const ceiling = waveformCeiling(bins(10_000), 'both')
    expect(waveformCeiling(bins(100), 'both', ceiling)).toBe(ceiling)
    expect(waveformCeiling(bins(0), 'both', ceiling)).toBe(ceiling)
    expect(waveformCeiling(bins(100), 'both')).toBeLessThan(ceiling)
  })

  it('adds headroom so small live changes do not resize every bar', () => {
    const ceiling = waveformCeiling(bins(1000), 'both')
    expect(ceiling).toBeGreaterThan(1000)
    expect(waveformCeiling(bins(1050), 'both', ceiling)).toBe(ceiling)
    const grown = waveformCeiling(bins(ceiling + 1), 'both', ceiling)
    expect(grown).toBeGreaterThan(ceiling + 1)
    expect(grown).toBeLessThanOrEqual(ceiling * 1.5)
    expect(waveformCeiling(bins(1, 100_000), 'both', grown)).toBeGreaterThanOrEqual(100_000)
  })

  it('keeps past rates unchanged when the live window advances between bucket boundaries', () => {
    const chunk = fixture.window.series[0] as TrafficChunk
    const start = chunk.start_ms
    const index = indexDestinationVolumes([chunk], start, fixture.window.coverage)
    const series = [{ id: seriesKey(chunk) } as MapSeries]
    const first = waveformGrid({ from: start - 100, to: start + 9900 }, 10)
    const moved = waveformGrid({ from: start + 100, to: start + 10100 }, 10)
    const before = wireWaveform(series, index, first, first.count)
    const after = wireWaveform(series, index, moved, moved.count)
    const beforeIndex = (start - first.from) / first.binMs
    const afterIndex = (start - moved.from) / moved.binMs
    expect(after[afterIndex].received).toBeGreaterThan(0)
    expect(after[afterIndex].received).toBe(before[beforeIndex].received)
    expect(first.binMs).toBe(moved.binMs)
    expect(moved.from).toBeLessThanOrEqual(start + 100)
    expect(moved.to).toBeGreaterThanOrEqual(start + 10100)
  })
})
