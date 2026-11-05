import { describe, expect, it } from 'vitest'
import { seriesKey, type TrafficChunk } from '@infrareveal/session-state'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { indexDestinationVolumes } from './destinationVolumes'
import type { MapSeries } from './mapTracks'
import { createWireWaveformCache, waveformCeiling, waveformGrid, wireWaveform, wireFlows, wireGaps } from './wireWaveform'

const bins = (received: number, sent = 0) => [[{ received, sent, complete: true, observed: true }]]

describe('steady timeline waveforms', () => {
  it('reuses unchanged geometry across live window replacements but publishes changed counters', () => {
    const chunk = fixture.window.series[0] as TrafficChunk
    const series = [{ id: seriesKey(chunk) } as MapSeries]
    const range = { from: chunk.start_ms, to: chunk.start_ms + chunk.chunk_ms }
    const cache = createWireWaveformCache()
    const original = cache(series, indexDestinationVolumes([chunk], 0, fixture.window.coverage), range)
    const refreshed = structuredClone(chunk)
    const replacement = indexDestinationVolumes([refreshed], 0, structuredClone(fixture.window.coverage))
    expect(cache(series, replacement, range)).toBe(original)
    expect(cache(series.map(item => ({ ...item, endMs: range.to + 1000 })), replacement, range)).toBe(original)
    refreshed.samples[0][2] += 1000
    const changed = cache(series, indexDestinationVolumes([refreshed], 0, fixture.window.coverage), range)
    expect(changed).not.toBe(original)
    expect(changed.reduce((sum, bin) => sum + bin.received, 0)).toBeGreaterThan(original.reduce((sum, bin) => sum + bin.received, 0))
  })
  it('holds the observed scale when a burst expires or becomes quieter', () => {
    const ceiling = waveformCeiling(bins(10_000), 'both')
    expect(waveformCeiling(bins(100), 'both', ceiling)).toBe(ceiling)
    expect(waveformCeiling(bins(0), 'both', ceiling)).toBe(ceiling)
    expect(waveformCeiling(bins(100), 'both')).toBeLessThan(ceiling)
  })

  it('adds headroom so small live changes do not resize every flow', () => {
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


describe('directional flow envelopes', () => {
  const measured = { received: 100, sent: 25, complete: true, observed: true }
  const quiet = { ...measured, received: 0, sent: 0 }
  it('splits at silence, capture gaps and certainty boundaries without inventing a connecting flow', () => {
    const samples = [measured, measured, quiet, measured, { ...quiet, observed: false }, { ...measured, complete: false }, measured]
    const flows = wireFlows(samples, 'received', 100)
    expect(flows).toHaveLength(4)
    expect(flows.map(flow => flow.partial)).toEqual([false, false, true, false])
    expect(flows[0].path).toMatch(/^M0,24 /)
    expect(flows[0].path.endsWith(`${2 * (1000 / 7)},24 Z`)).toBe(true)
    expect(flows[1].path.startsWith(`M${3 * (1000 / 7)},24 `)).toBe(true)
    expect(flows[1].path.endsWith(`${4 * (1000 / 7)},24 Z`)).toBe(true)
    expect(wireGaps(samples)).toEqual([{ x: 4 / 7 * 1000, width: 1 / 7 * 1000 }])
    expect(wireFlows([quiet, { ...measured, observed: false }], 'received', 100)).toEqual([])
  })

  it('uses a shared square-root scale on opposite sides of one baseline', () => {
    const received = wireFlows([measured], 'received', 100)[0]
    const sent = wireFlows([measured], 'sent', 100)[0]
    const bounds = (path: string) => {
      const ys = [...path.matchAll(/,(-?[\d.]+)/g)].map(match => Number(match[1]))
      return [Math.min(...ys), Math.max(...ys)]
    }
    expect(bounds(received.path)).toEqual([4, 24]) // 24 - 20 * sqrt(100/100)
    expect(bounds(sent.path)).toEqual([24, 34]) // 24 + 20 * sqrt(25/100)
    expect(wireFlows([measured], 'received', 1)[0].path).toBe(received.path)
  })
})
