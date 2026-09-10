import type { TimelineClip } from '../../model/sessionModel'
import type { CoverageRange } from '../../shared/activity/captureCoverage'
import { pixelAtTime, type TimeRange } from './trafficTime'

export type TrafficRateBin = { fromMs: number; toMs: number; incoming: number; outgoing: number; complete: boolean }
export type TrafficWaveform = { bins: (TrafficRateBin | null)[]; peakIn: number; peakOut: number }

/** A common, epoch-aligned averaging interval makes rates comparable at every zoom. */
export function trafficWaveforms(clips: readonly TimelineClip[], range: TimeRange, width: number, coverage: readonly CoverageRange[]) {
  const relevant = clips.filter(clip => clip.endMs > range.fromMs && clip.startMs < range.toMs)
  const resolution = relevant.reduce((max, clip) => clip.activity.samples.reduce((max, sample) =>
    sample.startMs < range.toMs && sample.startMs + sample.durationMs > range.fromMs ? Math.max(max, sample.durationMs) : max, max), 250)
  const desired = Math.max(resolution, (range.toMs - range.fromMs) / Math.max(1, Math.min(600, width / 6)))
  const binMs = [250, 500, 1000, 2000, 5000, 10_000, 30_000, 60_000, 300_000].find(ms => ms >= desired) ?? Math.ceil(desired / 300_000) * 300_000
  const series = new Map<string, TrafficWaveform>()
  let peak = 0
  for (const clip of relevant) {
    const samples = clip.activity.samples.filter(sample => sample.startMs < range.toMs && sample.startMs + sample.durationMs > range.fromMs)
    // Capture reports alone do not prove that this flow's detail has been loaded.
    if (!samples.length) continue
    const fromMs = Math.floor(Math.max(clip.startMs, range.fromMs) / binMs) * binMs
    const toMs = Math.ceil(Math.min(clip.endMs, range.toMs) / binMs) * binMs
    const observed = new Map<number, { incoming: number; outgoing: number; complete: boolean }>()
    for (const sample of samples) {
      const index = Math.floor((sample.startMs - fromMs) / binMs)
      const value = observed.get(index) ?? { incoming: 0, outgoing: 0, complete: true }
      value.incoming += sample.payloadBytesIn
      value.outgoing += sample.payloadBytesOut
      value.complete &&= sample.complete
      observed.set(index, value)
    }
    const bins: (TrafficRateBin | null)[] = []
    let peakIn = 0, peakOut = 0
    for (let start = fromMs, index = 0; start < toMs; start += binMs, index++) {
      const value = observed.get(index)
      const reports = coverage.filter(c => c.fromMs < start + binMs && c.toMs > start)
      const complete = reports.length > 0 && reports[0].fromMs <= start && reports[reports.length - 1].toMs >= start + binMs && reports.every(c => c.level === 'complete')
      if (!value && !complete) { bins.push(null); continue }
      // These are interval averages of observed payload, never prorated lifetime counters.
      const incoming = (value?.incoming ?? 0) * 1000 / binMs, outgoing = (value?.outgoing ?? 0) * 1000 / binMs
      peakIn = Math.max(peakIn, incoming); peakOut = Math.max(peakOut, outgoing)
      bins.push({ fromMs: start, toMs: start + binMs, incoming, outgoing, complete: complete && (value?.complete ?? true) })
    }
    series.set(clip.flowId, { bins, peakIn, peakOut })
    peak = Math.max(peak, peakIn, peakOut)
  }
  return { series, binMs, ceiling: rateCeiling(peak) }
}

function rateCeiling(peak: number) {
  if (peak <= 0) return 1
  const magnitude = 10 ** Math.floor(Math.log10(peak))
  return ([1, 2, 5, 10].find(step => step * magnitude >= peak) ?? 10) * magnitude
}

/** Piecewise-linear areas never overshoot measured averages or bridge missing capture. */
export function waveformPaths(bins: readonly (TrafficRateBin | null)[], direction: 'incoming' | 'outgoing', ceiling: number, range: TimeRange, width: number, height: number) {
  const center = height / 2, amplitude = Math.max(0, center - 2)
  const sign = direction === 'incoming' ? -1 : 1
  const paths: { line: string; area: string; complete: boolean }[] = []
  let run: TrafficRateBin[] = []
  const point = (time: number, rate: number) => `${pixelAtTime(time, width, range).toFixed(2)},${(center + sign * amplitude * Math.min(1, rate / Math.max(1, ceiling))).toFixed(2)}`
  const flush = () => {
    if (!run.length) return
    if (run.every(bin => bin[direction] === 0)) { run = []; return }
    const first = run[0], last = run[run.length - 1]
    const vertices = [point(first.fromMs, first[direction]), ...run.map(bin => point((bin.fromMs + bin.toMs) / 2, bin[direction])), point(last.toMs, last[direction])]
    paths.push({ line: `M${vertices.join(' L')}`, area: `M${point(first.fromMs, 0)} L${vertices.join(' L')} L${point(last.toMs, 0)} Z`, complete: run.every(bin => bin.complete) })
    run = []
  }
  for (const bin of bins) {
    if (!bin) { flush(); continue }
    if (run.length && run[run.length - 1].complete !== bin.complete) flush()
    run.push(bin)
  }
  flush()
  return paths
}
