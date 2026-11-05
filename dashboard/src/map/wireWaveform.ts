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
    if (entries.size > 1024) entries.delete(entries.keys().next().value!)
    return bins
  }
}
/** Rates divide only observed sample volume; missing intervals stay visible gaps. */
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
/** Smooth envelopes stay inside measured runs. Never bridge silence, missing
 * capture, or a change in certainty. Square-root radius keeps small exchanges
 * legible with the same scale across every lane and both directions. */
export function wireFlows(bins: WireBin[], direction: 'received' | 'sent', ceiling: number) {
  const flows: { path: string; center: string; partial: boolean }[] = []
  const baseline = direction === 'received' ? 17 : 47
  const width = 1000 / bins.length
  for (let first = 0; first < bins.length;) {
    if (!bins[first].observed || bins[first][direction] <= 0) { first++; continue }
    let end = first + 1
    while (end < bins.length && bins[end].observed && bins[end][direction] > 0 && bins[end].complete === bins[first].complete) end++
    const points = [
      { x: first * width, radius: 0 },
      ...bins.slice(first, end).map((bin, i) => ({ x: (first + i + .5) * width, radius: 13 * Math.sqrt(Math.min(1, bin[direction] / Math.max(1, ceiling))) })),
      { x: end * width, radius: 0 },
    ]
    const curve = (values: typeof points, sign: number) => values.slice(1).map((point, i) => {
      const previous = values[i], middle = (previous.x + point.x) / 2
      return `C${middle},${baseline + sign * previous.radius} ${middle},${baseline + sign * point.radius} ${point.x},${baseline + sign * point.radius}`
    }).join(' ')
    flows.push({
      path: `M${points[0].x},${baseline} ${curve(points, -1)} ${curve([...points].reverse(), 1)} Z`,
      center: `M${points[0].x},${baseline} H${points[points.length - 1].x}`,
      partial: !bins[first].complete,
    })
    first = end
  }
  return flows
}

/** Distinguish missing observation from a captured, quiet baseline. */
export function wireGaps(bins: WireBin[]) {
  const gaps: { x: number; width: number }[] = []
  for (let first = 0; first < bins.length;) {
    if (bins[first].observed) { first++; continue }
    let end = first + 1
    while (end < bins.length && !bins[end].observed) end++
    gaps.push({ x: first / bins.length * 1000, width: (end - first) / bins.length * 1000 })
    first = end
  }
  return gaps
}
