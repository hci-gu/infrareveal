import { captureQuality } from '@infrareveal/session-state'
import type { MapSeries } from './mapTracks'
import type { DestinationVolumeIndex } from './destinationVolumes'
import type { TrafficDirection } from './mapWorkspace'

export type WireBin = { received: number; sent: number; complete: boolean; observed: boolean }
export type WireRange = { from: number; to: number }

/** Anchor buckets to the clock so live panning cannot redistribute past traffic. */
export function waveformGrid(range: WireRange, count = 96) {
  const target = Math.max(1, (range.to - range.from) / Math.max(1, count))
  const magnitude = 10 ** Math.floor(Math.log10(target))
  const binMs = ([1, 2, 5, 10].find(step => step * magnitude >= target) ?? 10) * magnitude
  const from = Math.floor(range.from / binMs) * binMs
  const to = Math.max(from + binMs, Math.ceil(range.to / binMs) * binMs)
  return { from, to, binMs, count: Math.round((to - from) / binMs) }
}

/** A playhead or total change cannot invalidate immutable captured intervals. */
export function createWireWaveformCache() {
  const entries = new Map<string, { series: unknown[]; coverage: unknown; bins: WireBin[] }>()
  return (series: readonly MapSeries[], index: DestinationVolumeIndex, range: WireRange, count = 96) => {
    const ordered = [...series].sort((a, b) => a.id.localeCompare(b.id))
    const key = JSON.stringify([range.from, range.to, count, index.fromMs ?? 0, ordered.map(c => [c.id, c.startMs, c.endMs])])
    const captured = ordered.map(c => index.get(c.id))
    const cached = entries.get(key)
    if (cached && cached.coverage === index.coverage && captured.every((value, i) => value === cached.series[i])) return cached.bins
    const bins = wireWaveform(ordered, index, range, count)
    entries.set(key, { series: captured, coverage: index.coverage, bins })
    if (entries.size > 64) entries.delete(entries.keys().next().value!)
    return bins
  }
}
/** Rate bars divide only observed sample volume; missing intervals stay visible gaps. */
export function wireWaveform(series: readonly MapSeries[], index: DestinationVolumeIndex, range: WireRange, count = 96): WireBin[] {
  const duration = range.to - range.from
  if (count <= 0 || duration <= 0) return []
  const size = duration / count
  const bins = Array.from({ length: count }, (_, i) => {
    const quality = captureQuality(index.coverage ?? [], range.from + i*size, range.from + (i+1)*size)
    return { received: 0, sent: 0, complete: quality === 'complete', observed: quality !== 'unavailable' }
  })
  for (const item of series) for (const interval of index.get(item.id)?.intervals ?? []) {
    const start = Math.max(range.from, interval.start), end = Math.min(range.to, interval.end)
    if (end <= start) continue
    const first = Math.max(0, Math.floor((start-range.from)/size)), last = Math.min(count-1, Math.ceil((end-range.from)/size)-1)
    for (let i=first; i<=last; i++) {
      const overlap = Math.max(0, Math.min(end, range.from+(i+1)*size)-Math.max(start, range.from+i*size))
      const fraction = overlap/(interval.end-interval.start)
      bins[i].received += interval.received*fraction*1000/size; bins[i].sent += interval.sent*fraction*1000/size
      bins[i].observed = true; bins[i].complete &&= !interval.partial
    }
  }
  return bins
}
export function waveformCeiling(series: WireBin[][], direction: TrafficDirection, previous = 0) {
  let peak = 1
  for (const bins of series) for (const bin of bins) peak = Math.max(peak, direction === 'sent' ? 0 : bin.received, direction === 'received' ? 0 : bin.sent)
  if (peak <= previous) return previous
  // Hold the scale through quiet periods; new peaks get 25% breathing room.
  const step = 10 ** (Math.floor(Math.log10(peak)) - 1)
  return Math.ceil(peak * 1.25 / step) * step
}
/** Each bar is an interval average. Missing capture stays a gap, partial stays marked. */
export function wireBars(bins: WireBin[], direction: 'received' | 'sent', ceiling: number) {
  return bins.flatMap((bin, i) => !bin.observed || bin[direction] <= 0 ? [] : [{
    x: i / bins.length * 1000, width: 1000 / bins.length,
    height: Math.min(30, bin[direction] / ceiling * 30), partial: !bin.complete,
  }])
}
