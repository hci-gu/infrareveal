import { captureQuality, seriesKey } from '@infrareveal/session-state'
import type { CaptureInterval, MapWindow, TrafficChunk } from '@infrareveal/session-state'
import type { MapPosition, MapTimelineScene } from './mapModel'
import type { MapSeries } from './mapTracks'
import { hasMapCoordinates } from './mapCoordinates'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
type Interval = { start: number; end: number; received: number; sent: number; partial: boolean }
type VolumePart = { from: number; to: number; value: VolumeSeries }
type VolumeSeries = { parts?: VolumePart[]; peakRate: number; intervals: Interval[]; received: number[]; sent: number[]; lastActivity: number[] }
export type DestinationVolumeIndex = Map<string, VolumeSeries> & { fromMs?: number; toMs?: number; coverage?: CaptureInterval[]; peakRate?: number }
export type ByteTotals = { received: number; sent: number; partial: boolean }
export type DestinationVolume = ByteTotals & {
  id: string; position: MapPosition; location: string; bytes: number; height: number
  ips: string[]; seriesCount: number; tracks: DestinationColumn[]
  country?: CountryFootprint | null
}
export type DestinationColumn = ByteTotals & {
  trackId: string; label: string; bytes: number; destination: DestinationVolume
}


/** Wire totals and waveforms share the same captured bins as the map response. */
export function indexDestinationVolumes(chunks: readonly TrafficChunk[], fromMs = 0, coverage: CaptureInterval[] = [], toMs?: number): DestinationVolumeIndex {
  const index: DestinationVolumeIndex = new Map()
  for (const chunk of chunks) {
    const key = seriesKey(chunk), value = index.get(key) ?? { peakRate: 0, intervals: [], received: [0], sent: [0], lastActivity: [0] }
    for (const sample of chunk.samples) {
      const start = chunk.start_ms + sample[0], end = start + chunk.bucket_ms
      if (start < fromMs) continue
      value.intervals.push({ start, end, received: sample[2], sent: sample[1], partial: captureQuality(coverage, start, end) !== 'complete' })
    }
    index.set(key, value)
  }
  for (const value of index.values()) {
    value.intervals.sort((a,b) => a.end-b.end)
    for (const interval of value.intervals) { value.peakRate = Math.max(value.peakRate, interval.received * 1000 / (interval.end-interval.start), interval.sent * 1000 / (interval.end-interval.start)); value.received.push(value.received[value.received.length - 1] + interval.received); value.sent.push(value.sent[value.sent.length - 1] + interval.sent); value.lastActivity.push(interval.received + interval.sent > 0 ? interval.end : value.lastActivity[value.lastActivity.length - 1]) }
  }
  index.peakRate = Math.max(0, ...[...index.values()].map(value => value.peakRate))
  index.fromMs = fromMs; index.toMs = toMs; index.coverage = coverage
  return index
}
/** Prefix indexes belong to immutable segments, so a new tail never rebuilds
 * all historical samples. The small outer prefix joins segment totals. */
export function createDestinationVolumeCache() {
  const segments = new WeakMap<MapWindow, DestinationVolumeIndex>()
  let previous = new Map<string, VolumeSeries>()
  return (window: MapWindow): DestinationVolumeIndex => {
    const grouped = new Map<string, VolumePart[]>()
    for (const part of window.segments ?? [window]) {
      let captured = segments.get(part)
      if (!captured) { captured = indexDestinationVolumes(part.series, part.from_ms, part.coverage, part.to_ms); segments.set(part, captured) }
      for (const [key, value] of captured) {
        const values = grouped.get(key) ?? []
        values.push({ from: part.from_ms, to: part.to_ms, value }); grouped.set(key, values)
      }
    }
    const index: DestinationVolumeIndex = new Map()
    let peak = 0
    for (const [key, parts] of grouped) {
      const old = previous.get(key)
      let value = old?.parts?.length === parts.length && parts.every((part, i) => old.parts![i].value === part.value && old.parts![i].from === part.from && old.parts![i].to === part.to) ? old : undefined
      if (!value) {
        value = { parts, peakRate: 0, intervals: [], received: [0], sent: [0], lastActivity: [0] }
        for (const part of parts) {
          value.received.push(value.received[value.received.length - 1] + part.value.received[part.value.received.length - 1])
          value.sent.push(value.sent[value.sent.length - 1] + part.value.sent[part.value.sent.length - 1])
          value.lastActivity.push(Math.max(value.lastActivity[value.lastActivity.length - 1], part.value.lastActivity[part.value.lastActivity.length - 1]))
          value.peakRate = Math.max(value.peakRate, part.value.peakRate)
        }
      }
      index.set(key, value); peak = Math.max(peak, value.peakRate)
    }
    previous = index
    index.fromMs = window.from_ms; index.toMs = window.to_ms; index.coverage = window.coverage; index.peakRate = peak
    return index
  }
}

function prefixPosition(value: VolumeSeries, at: number, edge: 'start' | 'end') {
  let low = 0, high = value.parts?.length ?? value.intervals.length
  while (low < high) {
    const mid = (low + high) >>> 1
    const before = value.parts ? value.parts[mid].to <= at : edge === 'end' ? value.intervals[mid].end <= at : value.intervals[mid].start < at
    if (before) low = mid + 1; else high = mid
  }
  return low
}
function prefixVolume(value: VolumeSeries, at: number, edge: 'start' | 'end'): { sent: number; received: number } {
  const i = prefixPosition(value, at, edge)
  const partial = value.parts?.[i]
  const extra = partial && partial.from < at ? prefixVolume(partial.value, at, edge) : { sent: 0, received: 0 }
  return { sent: value.sent[i] + extra.sent, received: value.received[i] + extra.received }
}
function lastActivity(value: VolumeSeries, at: number): number {
  const i = prefixPosition(value, at, 'end'), partial = value.parts?.[i]
  return Math.max(value.lastActivity[i], partial && partial.from < at ? lastActivity(partial.value, at) : 0)
}
/** Waveforms visit only overlapping captured parts, preserving every bin. */
export function* volumeIntervals(value: VolumeSeries | undefined, from: number, to: number): Generator<Interval> {
  if (!value) return
  if (value.parts) {
    for (const part of value.parts) if (part.to > from && part.from < to) yield* volumeIntervals(part.value, from, to)
  } else {
    for (let i = prefixPosition(value, from, 'end'); i < value.intervals.length && value.intervals[i].start < to; i++) yield value.intervals[i]
  }
}
export function seriesVolume(series: MapSeries, index: DestinationVolumeIndex, cursorMs: number, fromMs = index.fromMs ?? 0): ByteTotals {
  const value = index.get(series.id)
  if (!value) return { received: 0, sent: 0, partial: true }
  const lower = prefixVolume(value, fromMs, 'start'), upper = prefixVolume(value, cursorMs, 'end')
  return { received: Math.max(0, upper.received - lower.received), sent: Math.max(0, upper.sent - lower.sent), partial: captureQuality(index.coverage ?? [], Math.max(index.fromMs ?? 0, fromMs, series.startMs), Math.min(cursorMs, series.endMs)) !== 'complete' }
}
/** Last completed traffic bin, never a future sample or attribution timestamp. */
export function seriesLastActivity(series: Pick<MapSeries, 'id'>, index: DestinationVolumeIndex, cursorMs: number) {
  const value = index.get(series.id)
  if (!value) return 0
  return lastActivity(value, cursorMs)
}
/** Each series contributes once, even when destinations share a location. */
export function projectDestinationVolumes(scene: MapTimelineScene, series: Map<string, MapSeries>, index: DestinationVolumeIndex, cursorMs: number, volumes?: ReadonlyMap<string, ByteTotals>): DestinationVolume[] {
  const groups = new Map<string, DestinationVolume>()
  const seenSeries = new Set<string>()
  for (const endpoint of scene.endpoints) {
    const country = countryFootprint(endpoint)
    const position = country?.position ?? endpoint.position
    if (!hasMapCoordinates(position[1], position[0])) continue
    if (endpoint.availableFromMs > cursorMs) continue
    const id = country ? `country:${country.code}` : endpoint.position.join(',')
    for (const item of endpoint.series) {
      const source = series.get(item.id)
      if (!source || seenSeries.has(item.id) || source.startMs > cursorMs) continue
      seenSeries.add(item.id)
      const volume = volumes?.get(source.id) ?? seriesVolume(source, index, cursorMs)
      const bytes = volume.received + volume.sent
      if (bytes <= 0) continue
      const group = groups.get(id) ?? {
        id, position, country, location: country?.name ?? ([endpoint.city, endpoint.country].filter(Boolean).join(', ') || endpoint.label),
        received: 0, sent: 0, bytes: 0, height: 0, partial: false, ips: [], seriesCount: 0, tracks: [],
      }
      group.received += volume.received; group.sent += volume.sent; group.bytes += bytes
      group.partial ||= volume.partial
      group.seriesCount += 1
      if (!group.ips.includes(endpoint.ip)) group.ips.push(endpoint.ip)
      let track = group.tracks.find(track => track.trackId === source.trackId)
      if (!track) {
        track = { trackId: source.trackId, label: source.label, received: 0, sent: 0, bytes: 0, partial: false, destination: group }
        group.tracks.push(track)
      }
      track.received += volume.received; track.sent += volume.sent; track.bytes += bytes
      track.partial ||= volume.partial
      groups.set(id, group)
    }
  }
  for (const group of groups.values()) {
    group.height = group.country ? 0 : destinationHeight(group.bytes)
    group.tracks.sort((a, b) => a.trackId.localeCompare(b.trackId))
  }
  return [...groups.values()].sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id))
}

/** Fixed logarithmic scale: adding a larger destination never shrinks others. */
function destinationHeight(bytes: number) {
  return bytes > 0 && Number.isFinite(bytes) ? 14 * Math.log2(1 + bytes / 4096) : 0
}

export function columnMetersPerPixel(latitude: number, zoom: number) {
  return 40_075_016.686 * Math.cos(Math.max(-85, Math.min(85, latitude)) * Math.PI / 180) / (512 * 2 ** zoom)
}

export type DirectionalColumn = DestinationColumn & { direction: number; base: number; height: number }
/** Paired, independently scaled sent/received stacks; track selection stays available. */
export function directionalColumns(destinations: DestinationVolume[]): DirectionalColumn[] {
  return destinations.filter(destination => !destination.country).flatMap(destination => (['received', 'sent'] as const).flatMap(key => {
      const height = destinationHeight(destination[key])
      let base = 0
      return destination.tracks.filter(track => track[key] > 0).map(track => {
        const column = { ...track, bytes: track[key], base, height: height * track[key] / destination[key], direction: key === 'sent' ? 1 : -1 }
        base += column.height
        return column
      })
    }))
}
