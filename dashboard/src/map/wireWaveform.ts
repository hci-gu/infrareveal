import type { MapConnection } from './mapTracks'
import type { DestinationVolumeIndex } from './destinationVolumes'
import type { TrafficDirection } from './mapWorkspace'

export type WireBin = { received: number; sent: number; complete: boolean; observed: boolean }
export type WireRange = { from: number; to: number }
/** Captured wire-byte averages, never interpolated lifetime counters or invented payload. */
export function wireWaveform(connections: readonly MapConnection[], index: DestinationVolumeIndex, range: WireRange, count = 96): WireBin[] {
  const duration = range.to - range.from
  if (count <= 0 || duration <= 0) return []
  const size = duration / count
  const bins = Array.from({ length: count }, () => ({ received: 0, sent: 0, complete: true, observed: false }))
  for (const connection of connections) {
    const covered = new Float64Array(count)
    const intervals = index.get(connection.flow.id)?.intervals ?? []
    for (const interval of intervals) {
      const start = Math.max(range.from, interval.start), end = Math.min(range.to, interval.end)
      if (end <= start || interval.end <= interval.start) continue
      const first = Math.max(0, Math.floor((start - range.from) / size)), last = Math.min(count - 1, Math.ceil((end - range.from) / size) - 1)
      for (let i = first; i <= last; i++) {
        const overlap = Math.max(0, Math.min(end, range.from + (i + 1) * size) - Math.max(start, range.from + i * size))
        const fraction = overlap / (interval.end - interval.start)
        bins[i].received += interval.received * fraction * 1000 / size
        bins[i].sent += interval.sent * fraction * 1000 / size
        bins[i].observed ||= overlap > 0
        bins[i].complete &&= !interval.partial
        covered[i] += overlap
      }
    }
    for (let i = 0; i < count; i++) {
      const expected = Math.max(0, Math.min(range.to, connection.endMs, range.from + (i + 1) * size) - Math.max(range.from, connection.startMs, range.from + i * size))
      if (covered[i] + 1 < expected) bins[i].complete = false
    }
  }
  return bins
}
export function waveformCeiling(series: WireBin[][], direction: TrafficDirection) {
  let peak = 1
  for (const bins of series) for (const bin of bins) peak = Math.max(peak, direction === 'sent' ? 0 : bin.received, direction === 'received' ? 0 : bin.sent)
  const magnitude = 10 ** Math.floor(Math.log10(peak))
  return ([1, 2, 5, 10].find(step => step * magnitude >= peak) ?? 10) * magnitude
}
/** Each bar is an interval average. Missing capture stays a gap, partial stays marked. */
export function wireBars(bins: WireBin[], direction: 'received' | 'sent', ceiling: number) {
  return bins.flatMap((bin, i) => !bin.observed || bin[direction] <= 0 ? [] : [{
    x: i / bins.length * 1000, width: 1000 / bins.length,
    height: Math.min(30, bin[direction] / ceiling * 30), partial: !bin.complete,
  }])
}
