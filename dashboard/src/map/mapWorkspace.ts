import { serviceKey } from '@infrareveal/session-state'
import { ACTIVITY_HOLD_MS, compareActivity } from './activityOrder'
import type { ActivityOrder } from './activityOrder'
import type { MapEndpoint, MapPosition, MapTimelineScene } from './mapModel'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
import { hasMapCoordinates } from './mapCoordinates'
import { seriesLastActivity, seriesVolume } from './destinationVolumes'
import type { ByteTotals, DestinationVolumeIndex } from './destinationVolumes'
import { sceneForTracks } from './mapTracks'
import type { MapSeries, MapTrack, MapTrackCatalog } from './mapTracks'

export const DEFAULT_TRAFFIC_FILTERS = { query: '', activeOnly: false, windowMs: 300_000, locationId: null }
export type WorkspaceState = { locationId: string | null; expanded: boolean; order?: ActivityOrder; query?: string; activeOnly?: boolean; windowMs?: number }
export const filterScope = (state: WorkspaceState) => JSON.stringify([state.locationId, state.query ?? '', state.activeOnly ?? false, state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs])
export function trafficFilterCount(state: WorkspaceState) {
  return Number(Boolean(state.query?.trim())) + Number(Boolean(state.locationId))
    + Number(Boolean(state.activeOnly))
    + Number((state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs) !== DEFAULT_TRAFFIC_FILTERS.windowMs)
}

export type LocationTraffic = ByteTotals & { id: string; label: string; detail: string; position?: MapPosition; country?: CountryFootprint | null; bytes: number; lastActivityMs: number; series: MapSeries[] }
export type TimelineTrafficRow = ByteTotals & { id: string; trackId: string; label: string; client: string; endpoint: string; location: string; locationId: string; series: MapSeries[]; bytes: number; lastActivityMs: number }
export const directionColor = (direction: number, light = false): [number, number, number] => direction === 1 ? light ? [168, 83, 32] : [239, 179, 120] : light ? [22, 123, 106] : [114, 222, 199]

function endpointLocation(endpoint: MapEndpoint): Pick<LocationTraffic, 'id' | 'label' | 'detail' | 'position' | 'country'> | null {
  const country = countryFootprint(endpoint)
  if (country) return { id: `country:${country.code}`, label: country.name, detail: 'Country estimate · city unknown', country, ...(hasMapCoordinates(country.position[1], country.position[0]) ? { position: country.position } : {}) }
  if (!hasMapCoordinates(endpoint.position[1], endpoint.position[0])) return null
  return { id: endpoint.position.join(','), label: endpoint.city || endpoint.country || endpoint.label, detail: [endpoint.city ? endpoint.country : '', 'Approximate IP location'].filter(Boolean).join(' · '), position: endpoint.position }
}
const zero = (): ByteTotals => ({ received: 0, sent: 0, partial: false })
function add(target: ByteTotals, value: ByteTotals) { target.received += value.received; target.sent += value.sent; target.partial ||= value.partial }

/** One aggregate series, one versioned location. Unlocated traffic participates in totals and timeline. */
export function projectWorkspace(catalog: MapTrackCatalog, scene: MapTimelineScene, index: DestinationVolumeIndex, cursor: number, state: WorkspaceState) {
  const byEndpoint = new Map(scene.endpoints.filter(e => e.availableFromMs <= cursor).map(e => [e.id, endpointLocation(e)]))
  const trackGroups = new Map<string, MapTrack>()
  const locations = new Map<string, LocationTraffic>()
  const rows: TimelineTrafficRow[] = []
  const bySeries = new Map<string, MapSeries>()
  const total = zero()
  const volumeBySeries = new Map<string, ByteTotals>()
  const locationOptions = new Map<string, { id: string; label: string }>()
  const terms = (state.query ?? '').toLowerCase().trim().split(/\s+/).filter(Boolean)
  for (const [id, chunks] of catalog.grouped) {
    const visible = chunks.filter(chunk => chunk.start_ms <= cursor)
    if (!visible.length) continue
    const first = visible[0]
    const startMs = first.start_ms + (first.samples[0]?.[0] ?? 0)
    if (startMs > cursor) continue
    const endMs = Math.max(startMs, seriesLastActivity({ id }, index, cursor))
    const destination = catalog.destinations.get(first.destination_id)
    const trackId = serviceKey(first)
    const series: MapSeries = {
      id, trackId, label: first.service_label || first.destination_ip,
      client: first.client_ip || first.client_id, site: first.service_key,
      hostname: first.evidence.hostname || first.destination_ip, chunks: visible,
      startMs, endMs, lastActivityMs: 0, bytes: 0, mapped: byEndpoint.has(id),
      location: destination ? [destination.city, destination.country].filter(Boolean).join(', ') : '', provider: destination?.provider || '',
    }
    const location = byEndpoint.get(series.id) ?? { id: 'unlocated', label: 'Unlocated', detail: 'Included in totals · no map position' }
    locationOptions.set(location.id, { id: location.id, label: location.label })
    const volume = seriesVolume(series, index, cursor, Math.max(index.fromMs ?? 0, cursor - (state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs)))
    const lastActivityMs = seriesLastActivity(series, index, cursor)
    const active = lastActivityMs > 0 && cursor - lastActivityMs < ACTIVITY_HOLD_MS
    if ((volume.received + volume.sent) <= 0 || lastActivityMs <= cursor - (state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs)) continue
    if (state.activeOnly && !active) continue
    if (terms.length) {
      const text = [series.label, series.site, series.hostname, series.client, series.provider, series.location, location.label,
      ...series.chunks.flatMap(chunk => [chunk.client_id, chunk.destination_ip, String(chunk.destination_port), chunk.protocol])].join(' ').toLowerCase()
      if (!terms.every(term => text.includes(term))) continue
    }
    if (state.locationId && state.locationId !== location.id) continue
    // Filter exact endpoint series once, before any map/list/timeline totals.
    const scoped = { ...series, lastActivityMs, bytes: (volume.received + volume.sent) }
    volumeBySeries.set(series.id, volume)
    const group = locations.get(location.id) ?? { ...location, ...zero(), bytes: 0, lastActivityMs: 0, series: [] }
    group.lastActivityMs = Math.max(group.lastActivityMs, lastActivityMs); add(group, volume); group.series.push(scoped); group.bytes = (group.received + group.sent)
    locations.set(group.id, group)
    add(total, volume)
    bySeries.set(series.id, scoped)
    const track = trackGroups.get(trackId) ?? { id: trackId, label: series.label, client: series.client, site: series.site, color: catalog.colors.get(trackId), series: [], lastActivityMs: 0, bytes: 0, mappedCount: 0 }
    track.series.push(scoped)
    track.lastActivityMs = Math.max(track.lastActivityMs, lastActivityMs)
    track.bytes += scoped.bytes
    track.mappedCount += Number(scoped.mapped)
    trackGroups.set(trackId, track)
    const chunk = series.chunks[0]
    rows.push({ id: series.id, trackId: series.trackId, label: series.label, client: series.client, endpoint: `${chunk.destination_ip}:${chunk.destination_port} · ${chunk.protocol.toUpperCase()}`, location: location.label, locationId: location.id, ...volume, lastActivityMs, bytes: scoped.bytes, series: [scoped] })
  }
  const tracks = [...trackGroups.values()].sort(compareActivity(state.order ?? 'volume'))
  for (const track of tracks) sortSeries(track.series, state.order)
  // Recorded default lanes stay stable; explicit sorting applies to every list.
  rows.sort(state.order ? compareActivity(state.order) : (a, b) => a.label.localeCompare(b.label) || a.client.localeCompare(b.client) || a.trackId.localeCompare(b.trackId) || a.series[0].startMs - b.series[0].startMs || a.id.localeCompare(b.id))
  return { locationOptions: [...locationOptions.values()].sort((a, b) => a.label.localeCompare(b.label)), locations: [...locations.values()].sort(compareActivity(state.order ?? 'volume')), rows, total, bySeries, tracks, volumeBySeries, scene: sceneForTracks(scene, bySeries) }
}

/** Detail drill-downs use only the globally filtered series at that location. */
export function scopeTracks(tracks: MapTrack[], bySeries: Map<string, MapSeries>, order?: ActivityOrder): MapTrack[] {
  return tracks.map(track => {
    const series = track.series.flatMap(c => bySeries.has(c.id) ? [bySeries.get(c.id)!] : [])
    sortSeries(series, order)
    return { ...track, series, lastActivityMs: Math.max(0, ...series.map(value => value.lastActivityMs)), bytes: series.reduce((sum, c) => sum + c.bytes, 0), mappedCount: series.filter(c => c.mapped).length }
  }).filter(track => track.series.length).sort(compareActivity(order ?? 'volume'))
}
export type WorkspaceProjection = ReturnType<typeof projectWorkspace>

function sortSeries(series: MapSeries[], order?: ActivityOrder) {
  series.sort(order === 'name' ? (a, b) => a.hostname.localeCompare(b.hostname) || a.id.localeCompare(b.id) : compareActivity(order ?? 'volume'))
}
