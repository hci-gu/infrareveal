import { seriesKey, serviceKey } from '@infrareveal/session-state'
import type { MapWindow, TrafficChunk } from '@infrareveal/session-state'
import type { MapTimelineScene } from './mapModel'
import type { TrafficProfile } from './mapTraffic'
type TrackColor = [number, number, number]
const PALETTE: TrackColor[] = [[104, 222, 193], [175, 148, 246], [247, 181, 100], [106, 184, 250], [239, 135, 160], [199, 216, 112], [104, 213, 230], [226, 164, 235], [239, 144, 101], [131, 201, 139], [162, 181, 226], [215, 198, 171]]


export type MapSeries = {
  id: string; trackId: string; label: string; client: string; site: string; hostname: string
  chunks: TrafficChunk[]; startMs: number; endMs: number; lastActivityMs: number; bytes: number; mapped: boolean; location: string; provider: string
}
export type MapTrack = { id: string; label: string; client: string; site: string; color: TrackColor; series: MapSeries[]; lastActivityMs: number; bytes: number; mappedCount: number }
export type MapTrackCatalog = ReturnType<typeof buildMapTrackCatalog>
/** Retain assigned colors across live revisions, independent of list sorting or selection. */
export class TrackColors {
  private colors = new Map<string, TrackColor>()
  retain(ids: Set<string>) { for (const id of this.colors.keys()) if (!ids.has(id)) this.colors.delete(id) }
  get size() { return this.colors.size }
  get(id: string): TrackColor {
    let color = this.colors.get(id)
    if (!color) {
      const index = this.colors.size
      color = index < PALETTE.length ? PALETTE[index] : hueColor((index * 137.508) % 360)
      this.colors.set(id, color)
    }
    return color
  }
}


export function buildMapTrackCatalog(window: MapWindow, colors = new TrackColors()) {
  const grouped = new Map<string, TrafficChunk[]>()
  for (const chunk of window.series) { const id = seriesKey(chunk); const group = grouped.get(id) ?? []; group.push(chunk); grouped.set(id, group) }
  for (const group of grouped.values()) group.sort((a, b) => a.start_ms - b.start_ms)
  const ids = new Set(window.series.map(serviceKey)); ids.forEach(id => colors.get(id)); colors.retain(ids)
  return { grouped, colors, fromMs: window.from_ms, toMs: window.to_ms, destinations: new Map(window.destinations.map(destination => [destination.id, destination])) }
}
export function sceneForTracks(scene: MapTimelineScene, bySeries: Map<string, MapSeries>): MapTimelineScene {
  return { ...scene, endpoints: scene.endpoints.flatMap(endpoint => {
    const series = endpoint.series.filter(item => bySeries.has(item.id)).map(item => ({ ...item, endMs: bySeries.get(item.id)!.endMs }))
    return series.length ? [{ ...endpoint, series }] : []
  }) }
}
export function seriesTraffic(series: MapSeries[], profiles: Map<string, TrafficProfile>) {
  const parts = series.map(series => profiles.get(series.id))
  return { rate: parts.reduce((sum, profile) => sum + (profile?.rates[0] ?? 0), 0), partial: series.some(series => !series.mapped) || parts.some(profile => !profile || profile.source === 'partial'), available: parts.some(profile => profile && profile.source !== 'unavailable') }
}
export function trackTraffic(track: MapTrack, profiles: Map<string, TrafficProfile>) {
  return seriesTraffic(track.series, profiles)
}
export function trackOpacity(trackId: string | undefined, selectedId: string | null) {
  return !selectedId || trackId === selectedId ? 1 : 0.09
}
export function colorCSS(color: TrackColor) { return `rgb(${color.join(' ')})` }
function hueColor(hue: number): TrackColor {
  const f = (n: number) => {
    const k = (n + hue / 30) % 12
    return Math.round(255 * (0.68 - 0.55 * 0.32 * Math.max(-1, Math.min(k - 3, 9 - k, 1))))
  }
  return [f(0), f(8), f(4)]
}
