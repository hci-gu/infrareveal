import { directionalBytes } from './mapWorkspace'
import type { TimelineTrafficRow, TrafficDirection } from './mapWorkspace'
import type { DestinationVolumeIndex } from './destinationVolumes'
import type { WireRange } from './wireWaveform'

/** Completed, directional samples inside the visible window own lane activity;
 * lifetime totals and a series' last-seen metadata cannot make a lane active. */
export function timelineLanes(rows: TimelineTrafficRow[], index: DestinationVolumeIndex, range: WireRange, cursorMs: number, direction: TrafficDirection) {
  const to = Math.min(range.to, cursorMs)
  return rows.map(row => {
    let lastActivityMs = 0, bytes = 0
    for (const series of row.series) for (const interval of index.get(series.id)?.intervals ?? []) {
      if (interval.end <= range.from || interval.end > to) continue
      const volume = directionalBytes(interval, direction)
      if (volume <= 0) continue
      lastActivityMs = Math.max(lastActivityMs, interval.end)
      bytes += volume * (interval.end - Math.max(range.from, interval.start)) / (interval.end - interval.start)
    }
    const quietMs = Math.max(0, to - lastActivityMs)
    const recentlyActive = bytes > 0 && quietMs < 30_000
    // Keep the full history readable as a lane settles; only recent traffic
    // gets full emphasis. Holding the window also holds this emphasis.
    const activityOpacity = bytes > 0 ? 1 - .5 * Math.min(1, Math.max(0, quietMs - 30_000) / 120_000) : .35
    return { ...row, windowBytes: bytes, windowLastActivityMs: lastActivityMs, recentlyActive, activityOpacity }
  })
}
