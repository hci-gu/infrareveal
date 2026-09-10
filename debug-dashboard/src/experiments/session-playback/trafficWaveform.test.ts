import { describe, expect, it } from 'vitest'
import type { TimelineClip } from '../../model/sessionModel'
import type { FlowActivitySample } from '../../shared/activity/decodeActivityChunk'
import type { CoverageRange } from '../../shared/activity/captureCoverage'
import { trafficWaveforms, waveformPaths } from './trafficWaveform'

const sample = (startMs: number, durationMs: number, incoming: number, outgoing = 0): FlowActivitySample => ({ startMs, durationMs, payloadBytesIn: incoming, payloadBytesOut: outgoing, packetsIn: 1, packetsOut: 1, complete: true })
const clip = (id: string, samples: FlowActivitySample[]): TimelineClip => ({ flowId: id, startMs: 0, endMs: 10_000, activity: { samples } } as TimelineClip)
const coverage = (fromMs: number, toMs: number, level: CoverageRange['level'] = 'complete'): CoverageRange => ({ fromMs, toMs, level, detail: level })

describe('Traffic rate waveforms', () => {
  it('compares traffic on one shared linear scale without per-flow normalization or minimum spikes', () => {
    const range = { fromMs: 0, toMs: 1000 }
    const model = trafficWaveforms([clip('small', [sample(0, 1000, 1000, 1000)]), clip('large', [sample(0, 1000, 10_000)])], range, 600, [coverage(0, 1000)])
    expect(model.ceiling).toBe(10_000)
    expect(model.series.get('small')?.peakIn).toBe(1000)
    const small = waveformPaths(model.series.get('small')!.bins, 'incoming', model.ceiling, range, 100, 100)
    const large = waveformPaths(model.series.get('large')!.bins, 'incoming', model.ceiling, range, 100, 100)
    const sent = waveformPaths(model.series.get('small')!.bins, 'outgoing', model.ceiling, range, 100, 100)
    expect(small[0].line).toContain('50.00,45.20')
    expect(large[0].line).toContain('50.00,2.00')
    expect(sent[0].line).toContain('50.00,54.80')
  })

  it('converts byte buckets of different durations into comparable bytes per second', () => {
    const fine = Array.from({ length: 20 }, (_, i) => sample(i * 250, 250, 250, 50))
    const coarse = [sample(0, 5000, 5000, 1000)]
    const model = trafficWaveforms([clip('fine', fine), clip('coarse', coarse)], { fromMs: 0, toMs: 5000 }, 600, [coverage(0, 5000)])
    expect(model.binMs).toBe(5000)
    expect(model.series.get('fine')).toEqual(model.series.get('coarse'))
    expect(model.series.get('fine')?.bins[0]).toMatchObject({ incoming: 1000, outgoing: 200 })
  })

  it('keeps a known quiet interval at zero and breaks curves at unknown capture', () => {
    const source = [clip('flow', [sample(0, 1000, 1000), sample(2000, 1000, 2000)])]
    const range = { fromMs: 0, toMs: 3000 }
    const known = trafficWaveforms(source, range, 600, [coverage(0, 3000)]).series.get('flow')!
    expect(known.bins[1]?.incoming).toBe(0)
    const missing = trafficWaveforms(source, range, 600, [coverage(0, 1000), coverage(1000, 2000, 'unknown'), coverage(2000, 3000)]).series.get('flow')!
    expect(missing.bins[1]).toBeNull()
    expect(waveformPaths(missing.bins, 'incoming', 2000, range, 300, 100)).toHaveLength(2)
  })

  it('does not turn packet-only observations into visible payload spikes or unloaded flows into silence', () => {
    const range = { fromMs: 0, toMs: 1000 }
    const model = trafficWaveforms([clip('packets', [sample(0, 1000, 0)]), clip('unloaded', [])], range, 600, [coverage(0, 1000)])
    expect(model.series.has('unloaded')).toBe(false)
    expect(model.series.get('packets')?.peakIn).toBe(0)
    expect(waveformPaths(model.series.get('packets')!.bins, 'outgoing', model.ceiling, range, 300, 100)).toEqual([])
  })

  it('retains coarse interval averages at partial viewport boundaries and identifies incomplete samples', () => {
    const model = trafficWaveforms([clip('coarse', [{ ...sample(0, 5000, 5000), complete: false }])], { fromMs: 2500, toMs: 7500 }, 600, [coverage(0, 10_000)])
    expect(model.series.get('coarse')?.bins[0]).toEqual({ fromMs: 0, toMs: 5000, incoming: 1000, outgoing: 0, complete: false })
    expect(model.ceiling).toBe(1000)
  })

  it('keeps aggregation epoch-aligned when the viewport pans and rounds the shared ceiling upward', () => {
    const source = [clip('flow', [sample(3000, 1000, 1200)])]
    const before = trafficWaveforms(source, { fromMs: 0, toMs: 5000 }, 60, [coverage(0, 10_000)])
    const after = trafficWaveforms(source, { fromMs: 500, toMs: 5500 }, 60, [coverage(0, 10_000)])
    expect(before.ceiling).toBe(2000)
    expect(after.series.get('flow')?.bins.find(bin => bin?.fromMs === 3000)).toEqual(before.series.get('flow')?.bins.find(bin => bin?.fromMs === 3000))
  })
})
