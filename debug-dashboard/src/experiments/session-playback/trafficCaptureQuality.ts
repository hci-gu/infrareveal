import type { Flow } from '@infrareveal/session-state'
import type { TimelineClip } from '../../model/sessionModel'
import type { TimeRange } from './trafficTime'

export type CaptureShortfall = { capturedBytes: number; totalBytes: number }
export type LoadedTrafficRange = TimeRange & { flowIds: readonly string[] }

/** Compare completed history requests with final flow counters, never a partial viewport. */
export function captureShortfalls(clips: readonly TimelineClip[], flows: ReadonlyMap<string, Flow>, loaded: readonly LoadedTrafficRange[]) {
  const result = new Map<string, CaptureShortfall>()
  for (const clip of clips) {
    const flow = flows.get(clip.flowId)
    if (!flow) continue
    const start = Date.parse(flow.start), end = Date.parse(flow.last_seen)
    if (!Number.isFinite(start) || !Number.isFinite(end) || end < start) continue
    let coveredTo = start
    for (const range of loaded.filter(range => range.flowIds.includes(flow.id)).sort((a, b) => a.fromMs - b.fromMs)) {
      if (range.fromMs > coveredTo) break
      coveredTo = Math.max(coveredTo, range.toMs)
    }
    if (coveredTo <= start || coveredTo < end) continue
    // Conntrack counts IP bytes; capture includes link headers. A large deficit
    // (over half, and at least 64 KiB) cannot be explained by that overhead.
    const shortfall = (counter: number, captured: number) => Number.isFinite(counter) && Number.isFinite(captured) && counter - captured >= 65_536 && captured < counter / 2
    const { wireBytesIn, wireBytesOut } = clip.activity
    if (shortfall(flow.bytes_in, wireBytesIn) || shortfall(flow.bytes_out, wireBytesOut)) {
      result.set(flow.id, { capturedBytes: wireBytesIn + wireBytesOut, totalBytes: flow.bytes_in + flow.bytes_out })
    }
  }
  return result
}
