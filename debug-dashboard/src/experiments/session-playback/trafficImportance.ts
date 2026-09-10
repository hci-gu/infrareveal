import type { Flow, FlowActivityChunk, FlowActivityWindow } from '@infrareveal/session-state'
import { captureCoverage } from '../../shared/activity/captureCoverage'
import { decodeActivityChunk } from '../../shared/activity/decodeActivityChunk'
import { preferredActivityChunks, type TrafficGroup } from './trafficModel'

export type TrafficImportanceMode = 'total' | 'recent' | 'equal'
export type TrafficVolume = { bytes: number | null; complete: boolean }
export const RECENT_TRAFFIC_MS = 30_000

/** Rank every flow from the same evidence, independently of which rows are on screen. */
export function trafficVolumes(flows: Map<string, Flow>, mode: TrafficImportanceMode, chunks: readonly FlowActivityChunk[], windows: readonly FlowActivityWindow[], cursorMs: number) {
  const result = new Map<string, TrafficVolume>()
  const fromMs = cursorMs - RECENT_TRAFFIC_MS
  const coverage = mode === 'recent' ? captureCoverage(windows, fromMs, cursorMs) : []
  const captured = new Map<string, { bytes: number; complete: boolean }>()
  if (mode === 'recent') {
    for (const chunk of preferredActivityChunks(chunks)) {
      for (const sample of decodeActivityChunk(chunk)) {
        // No future bytes or invented fractions of a boundary bucket during replay.
        if (sample.startMs < fromMs || sample.startMs + sample.durationMs > cursorMs) continue
        const value = captured.get(chunk.flow) ?? { bytes: 0, complete: true }
        value.bytes += sample.payloadBytesIn + sample.payloadBytesOut
        value.complete &&= sample.complete
        captured.set(chunk.flow, value)
      }
    }
  }
  for (const flow of flows.values()) {
    if (mode !== 'recent') {
      const known = [flow.bytes_in, flow.bytes_out].every(value => Number.isFinite(value) && value >= 0)
      result.set(flow.id, { bytes: known ? flow.bytes_in + flow.bytes_out : null, complete: known })
      continue
    }
    const start = Math.max(fromMs, Date.parse(flow.start)), end = Math.min(cursorMs, Date.parse(flow.last_seen))
    const observed = captured.get(flow.id)
    const relevant = coverage.filter(range => range.fromMs < end && range.toMs > start)
    const complete = end <= start || relevant.length > 0 && relevant.every(range => range.level === 'complete')
    result.set(flow.id, { bytes: observed?.bytes ?? (complete ? 0 : null), complete: complete && (observed?.complete ?? true) })
  }
  return result
}

export function importanceLayout(groups: TrafficGroup[], volumes: Map<string, TrafficVolume>, mode: TrafficImportanceMode, contrast: number) {
  const maximum = groups.reduce((max, group) => group.clips.reduce((max, clip) => Math.max(max, volumes.get(clip.flowId)?.bytes ?? 0), max), 0)
  const groupVolumes = new Map(groups.map(group => {
    const known = group.clips.flatMap(clip => { const bytes = volumes.get(clip.flowId)?.bytes; return bytes == null ? [] : [bytes] })
    return [group.id, { bytes: known.length ? known.reduce((sum, bytes) => sum + bytes, 0) : null, complete: group.clips.every(clip => volumes.get(clip.flowId)?.complete) }]
  }))
  const groupBytes = new Map([...groupVolumes].map(([id, volume]) => [id, volume.bytes ?? 0]))
  const totalBytes = [...groupBytes.values()].reduce((sum, bytes) => sum + bytes, 0)
  const weighted = mode !== 'equal'
  const ordered = weighted ? groups.map(group => ({ ...group, clips: [...group.clips].sort((a, b) => (volumes.get(b.flowId)?.bytes ?? -1) - (volumes.get(a.flowId)?.bytes ?? -1) || a.startMs - b.startMs || a.flowId.localeCompare(b.flowId)) }))
    .sort((a, b) => Number(b.clips.length > 0) - Number(a.clips.length > 0) || groupBytes.get(b.id)! - groupBytes.get(a.id)! || a.id.localeCompare(b.id)) : groups
  const strengths = new Map(groups.flatMap(group => group.clips.map(clip => [clip.flowId, maximum > 0 ? Math.sqrt((volumes.get(clip.flowId)?.bytes ?? 0) / maximum) : 0] as const)))
  // Square-root compression keeps small connections readable alongside large downloads.
  const height = (flowId: string) => weighted ? 36 + Math.round((strengths.get(flowId) ?? 0) * 88 * Math.max(0, Math.min(100, contrast)) / 100) : 36
  return { groups: ordered, groupBytes, groupVolumes, totalBytes, strengths, height }
}
