import type { FlowActivityWindow } from '@infrareveal/session-state'
export type CoverageRange = { fromMs: number; toMs: number; level: 'complete' | 'partial' | 'unavailable' | 'unknown'; detail: string }
/** Partition overlapping reports, preferring the most severe observation at each time. */
export function captureCoverage(windows: readonly FlowActivityWindow[], fromMs: number, toMs: number): CoverageRange[] {
  const relevant = windows.map(window => ({ window, start: Date.parse(window.window_start), end: Date.parse(window.window_start) + window.window_ms }))
    .filter(item => Number.isFinite(item.start) && item.end > fromMs && item.start < toMs)
  const points = [...new Set([fromMs, toMs, ...relevant.flatMap(item => [Math.max(fromMs, item.start), Math.min(toMs, item.end)])])].sort((a, b) => a - b)
  const result: CoverageRange[] = []
  for (let i = 0; i < points.length - 1; i++) {
    const from = points[i], to = points[i + 1]
    const reports = relevant.filter(item => item.start <= from && item.end >= to).map(item => item.window)
    const unavailable = reports.find(w => !w.capture_running || w.last_error)
    const partial = reports.find(w => !w.capture_complete || w.dropped_events > 0)
    const level = unavailable ? 'unavailable' : partial ? 'partial' : reports.length ? 'complete' : 'unknown'
    const detail = unavailable ? unavailable.last_error || 'Capture was not running' : partial ? 'Incomplete capture; activity may be missing' : reports.length ? 'Complete capture' : 'No loaded completeness window'
    const previous = result[result.length - 1]
    if (previous?.level === level && previous.detail === detail) previous.toMs = to
    else result.push({ fromMs: from, toMs: to, level, detail })
  }
  return result
}
