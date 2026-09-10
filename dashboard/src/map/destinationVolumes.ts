import { parseEpoch } from '@infrareveal/session-state'
import type { FlowActivityChunk } from '@infrareveal/session-state'
import type { MapPosition, MapTimelineScene } from './mapModel'
import type { MapConnection } from './mapTracks'

export type VolumeChunk = Pick<FlowActivityChunk, 'id' | 'session' | 'flow' | 'chunk_start' | 'chunk_ms' | 'wire_bytes_in' | 'wire_bytes_out' | 'capture_complete' | 'dropped_events' | 'updated_at_source' | 'updated'>
type Interval = { start: number; end: number; received: number; sent: number; partial: boolean }
type VolumeSeries = { intervals: Interval[]; received: number[]; sent: number[]; partial: number[] }
export type DestinationVolumeIndex = Map<string, VolumeSeries>
export type ByteTotals = { received: number; sent: number; estimated: boolean; partial: boolean }
export type DestinationVolume = ByteTotals & {
  id: string; position: MapPosition; location: string; bytes: number; height: number
  ips: string[]; flowCount: number; tracks: DestinationColumn[]
}
export type DestinationColumn = ByteTotals & {
  trackId: string; label: string; bytes: number; base: number; height: number; destination: DestinationVolume
}

/** Compact wire counters, independent of the evictable activity/rate window. */
export function indexDestinationVolumes(records: readonly VolumeChunk[]): DestinationVolumeIndex {
  const unique = new Map<string, VolumeChunk>()
  for (const record of records) {
    const previous = unique.get(record.id)
    if (!previous || revision(record) >= revision(previous)) unique.set(record.id, record)
  }
  const flows = new Map<string, Map<number, VolumeChunk>>()
  for (const record of unique.values()) {
    const start = parseEpoch(record.chunk_start, NaN)
    if (!record.flow || !Number.isFinite(start) || !Number.isFinite(record.chunk_ms) || record.chunk_ms <= 0 || record.chunk_ms > 60_000
      || !validBytes(record.wire_bytes_in) || !validBytes(record.wire_bytes_out)) continue
    const chunks = flows.get(record.flow) ?? new Map<number, VolumeChunk>()
    const previous = chunks.get(start)
    if (!previous || revision(record) >= revision(previous)) chunks.set(start, record)
    flows.set(record.flow, chunks)
  }
  return new Map([...flows].map(([flow, chunks]) => {
    const series: VolumeSeries = { intervals: [], received: [0], sent: [0], partial: [0] }
    for (const [start, chunk] of [...chunks].sort(([a], [b]) => a - b)) {
      // Wire counters have chunk-level timing; the last packet bounds growth.
      const end = Math.max(start, Math.min(start + chunk.chunk_ms, parseEpoch(chunk.updated_at_source, start + chunk.chunk_ms)))
      const interval = { start, end, received: chunk.wire_bytes_in, sent: chunk.wire_bytes_out, partial: !chunk.capture_complete || chunk.dropped_events > 0 }
      series.intervals.push(interval)
      series.received.push(series.received[series.received.length - 1] + interval.received)
      series.sent.push(series.sent[series.sent.length - 1] + interval.sent)
      series.partial.push(series.partial[series.partial.length - 1] + Number(interval.partial))
    }
    return [flow, series]
  }))
}

export function connectionVolume(connection: MapConnection, index: DestinationVolumeIndex, cursorMs: number): ByteTotals {
  const empty = { received: 0, sent: 0, estimated: false, partial: false }
  if (cursorMs < connection.startMs) return empty
  const series = index.get(connection.flow.id)
  if (!series) {
    const fraction = elapsedFraction(cursorMs, connection.startMs, connection.endMs)
    return { received: safeBytes(connection.flow.bytes_in) * fraction, sent: safeBytes(connection.flow.bytes_out) * fraction, estimated: true, partial: false }
  }
  let low = 0, high = series.intervals.length
  while (low < high) {
    const middle = (low + high) >>> 1
    if (series.intervals[middle].start <= cursorMs) low = middle + 1
    else high = middle
  }
  if (!low) return empty
  const i = low - 1, chunk = series.intervals[i]
  const fraction = elapsedFraction(cursorMs, Math.max(chunk.start, connection.startMs), chunk.end)
  return {
    received: series.received[i] + chunk.received * fraction,
    sent: series.sent[i] + chunk.sent * fraction,
    estimated: false, partial: series.partial[i] > 0 || (fraction > 0 && chunk.partial),
  }
}

/** Each connection contributes once, regardless of route splits or hop count. */
export function projectDestinationVolumes(scene: MapTimelineScene, connections: Map<string, MapConnection>, index: DestinationVolumeIndex, cursorMs: number, visibleIPs?: Set<string>): DestinationVolume[] {
  const groups = new Map<string, DestinationVolume>()
  const seenFlows = new Set<string>()
  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > cursorMs || (visibleIPs && !visibleIPs.has(endpoint.ip))) continue
    const id = endpoint.position.join(',')
    for (const flow of endpoint.flows) {
      const connection = connections.get(flow.id)
      if (!connection || seenFlows.has(flow.id) || connection.startMs > cursorMs) continue
      seenFlows.add(flow.id)
      const volume = connectionVolume(connection, index, cursorMs)
      const bytes = volume.received + volume.sent
      if (bytes <= 0) continue
      const group = groups.get(id) ?? {
        id, position: endpoint.position, location: [endpoint.city, endpoint.country].filter(Boolean).join(', ') || endpoint.label,
        received: 0, sent: 0, bytes: 0, height: 0, estimated: false, partial: false, ips: [], flowCount: 0, tracks: [],
      }
      group.received += volume.received; group.sent += volume.sent; group.bytes += bytes
      group.estimated ||= volume.estimated; group.partial ||= volume.partial
      group.flowCount += 1
      if (!group.ips.includes(endpoint.ip)) group.ips.push(endpoint.ip)
      let track = group.tracks.find(track => track.trackId === connection.id)
      if (!track) {
        track = { trackId: connection.id, label: connection.label, received: 0, sent: 0, bytes: 0, height: 0, base: 0, estimated: false, partial: false, destination: group }
        group.tracks.push(track)
      }
      track.received += volume.received; track.sent += volume.sent; track.bytes += bytes
      track.estimated ||= volume.estimated; track.partial ||= volume.partial
      groups.set(id, group)
    }
  }
  for (const group of groups.values()) {
    group.height = destinationHeight(group.bytes)
    group.tracks.sort((a, b) => a.trackId.localeCompare(b.trackId))
    let base = 0
    for (const track of group.tracks) {
      track.base = base
      track.height = group.height * track.bytes / group.bytes
      base += track.height
    }
  }
  return [...groups.values()].sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id))
}

/** Fixed logarithmic scale: adding a larger destination never shrinks others. */
export function destinationHeight(bytes: number) {
  return bytes > 0 && Number.isFinite(bytes) ? 14 * Math.log2(1 + bytes / 4096) : 0
}

export function columnMetersPerPixel(latitude: number, zoom: number) {
  return 40_075_016.686 * Math.cos(Math.max(-85, Math.min(85, latitude)) * Math.PI / 180) / (512 * 2 ** zoom)
}

function elapsedFraction(cursor: number, start: number, end: number) {
  return cursor < start ? 0 : end <= start ? 1 : Math.max(0, Math.min(1, (cursor - start) / (end - start)))
}
function revision(chunk: VolumeChunk) { return parseEpoch(chunk.updated || chunk.updated_at_source, 0) }
function validBytes(value: unknown): value is number { return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0 }
function safeBytes(value: number) { return validBytes(value) ? value : 0 }
