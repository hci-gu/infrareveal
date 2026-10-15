import { captureQuality, seriesKey } from '@infrareveal/session-state'
import type { CaptureInterval, TrafficChunk } from '@infrareveal/session-state'
import type { MapPosition, MapTimelineScene } from './mapModel'
import type { MapSeries } from './mapTracks'
import { hasMapCoordinates } from './mapRoutes'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
type Interval = { start: number; end: number; received: number; sent: number; partial: boolean }
type VolumeSeries = { intervals: Interval[]; received: number[]; sent: number[]; partial: number[] }
export type DestinationVolumeIndex = Map<string, VolumeSeries> & { fromMs?: number; coverage?: CaptureInterval[] }
export type ByteTotals = { received: number; sent: number; partial: boolean }
export type DestinationVolume = ByteTotals & {
  id: string; position: MapPosition; location: string; bytes: number; height: number
  ips: string[]; seriesCount: number; tracks: DestinationColumn[]
  country?: CountryFootprint | null
}
export type DestinationColumn = ByteTotals & {
  trackId: string; label: string; bytes: number; base: number; height: number; destination: DestinationVolume
}


/** Wire totals and waveforms share the same captured bins as the map response. */
export function indexDestinationVolumes(chunks: readonly TrafficChunk[], fromMs = 0, coverage: CaptureInterval[] = []): DestinationVolumeIndex {
  const index: DestinationVolumeIndex = new Map()
  for (const chunk of chunks) {
    const key = seriesKey(chunk), value = index.get(key) ?? { intervals: [], received: [0], sent: [0], partial: [0] }
    for (const sample of chunk.samples) {
      const start = chunk.start_ms + sample[0], end = start + chunk.bucket_ms
      if (start < fromMs) continue
      value.intervals.push({ start, end, received: sample[2], sent: sample[1], partial: captureQuality(coverage, start, end) !== 'complete' })
    }
    index.set(key, value)
  }
  for (const value of index.values()) {
    value.intervals.sort((a,b) => a.end-b.end)
    for (const interval of value.intervals) { value.received.push(value.received[value.received.length - 1] + interval.received); value.sent.push(value.sent[value.sent.length - 1] + interval.sent); value.partial.push(value.partial[value.partial.length - 1] + Number(interval.partial)) }
  }
  index.fromMs = fromMs; index.coverage = coverage
  return index
}
export function seriesVolume(series: MapSeries, index: DestinationVolumeIndex, cursorMs: number): ByteTotals {
  const value = index.get(series.id)
  if (!value) return { received: 0, sent: 0, partial: true }
  let low = 0, high = value.intervals.length
  while (low < high) { const middle = (low+high) >>> 1; if (value.intervals[middle].end <= cursorMs) low = middle+1; else high = middle }
  return { received: value.received[low], sent: value.sent[low], partial: captureQuality(index.coverage ?? [], Math.max(index.fromMs ?? 0, series.startMs), Math.min(cursorMs, series.endMs)) !== 'complete' }
}
/** Each series contributes once, regardless of route splits or hop count. */
export function projectDestinationVolumes(scene: MapTimelineScene, series: Map<string, MapSeries>, index: DestinationVolumeIndex, cursorMs: number, visibleIPs?: Set<string>): DestinationVolume[] {
  const groups = new Map<string, DestinationVolume>()
  const seenSeries = new Set<string>()
  for (const endpoint of scene.endpoints) {
    const country = countryFootprint(endpoint)
    const position = country?.position ?? endpoint.position
    if (!hasMapCoordinates(position[1], position[0])) continue
    if (endpoint.availableFromMs > cursorMs || (visibleIPs && !visibleIPs.has(endpoint.ip))) continue
    const id = country ? `country:${country.code}` : endpoint.position.join(',')
    for (const item of endpoint.series) {
      const source = series.get(item.id)
      if (!source || seenSeries.has(item.id) || source.startMs > cursorMs) continue
      seenSeries.add(item.id)
      const volume = seriesVolume(source, index, cursorMs)
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
        track = { trackId: source.trackId, label: source.label, received: 0, sent: 0, bytes: 0, height: 0, base: 0, partial: false, destination: group }
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

export type DirectionalColumn = DestinationColumn & { direction: number }
/** Paired, independently scaled sent/received stacks; track selection stays available. */
export function directionalColumns(destinations: DestinationVolume[], direction: 'both' | 'received' | 'sent'): DirectionalColumn[] {
  return destinations.filter(destination => !destination.country).flatMap(destination => (['received', 'sent'] as const)
    .filter(key => direction === 'both' || direction === key).flatMap(key => {
      const height = destinationHeight(destination[key])
      let base = 0
      return destination.tracks.filter(track => track[key] > 0).map(track => {
        const column = { ...track, bytes: track[key], base, height: height * track[key] / destination[key], direction: key === 'sent' ? 1 : -1 }
        base += column.height
        return column
      })
    }))
}
