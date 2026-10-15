import type { MapEndpoint, MapPosition, MapTimelineScene } from './mapModel'
import { countryFootprint } from './countryFootprints'
import type { CountryFootprint } from './countryFootprints'
import { hasMapCoordinates } from './mapRoutes'
import { seriesVolume } from './destinationVolumes'
import type { ByteTotals, DestinationVolumeIndex } from './destinationVolumes'
import { projectMapTracks, sceneForTracks } from './mapTracks'
import type { MapSeries, MapTrack, MapTrackCatalog } from './mapTracks'

export type TrafficDirection = 'both' | 'received' | 'sent'
export type WorkspaceState = { direction: TrafficDirection; locationId: string | null; expanded: boolean }
export type LocationTraffic = ByteTotals & { id: string; label: string; detail: string; position?: MapPosition; country?: CountryFootprint | null; bytes: number; series: MapSeries[] }
export type TimelineTrafficRow = ByteTotals & { id: string; trackId: string; label: string; client: string; location: string; locationId: string; series: MapSeries[]; bytes: number }
export const directionalBytes = (value: { received: number; sent: number }, direction: TrafficDirection) => direction === 'both' ? value.received + value.sent : value[direction]
export const directionLabel = (direction: TrafficDirection) => direction === 'received' ? 'Downloaded' : direction === 'sent' ? 'Sent' : 'Downloaded + sent'
export const directionColor = (direction: number, light = false): [number, number, number] => direction === 1 ? light ? [168, 83, 32] : [239, 179, 120] : light ? [22, 123, 106] : [114, 222, 199]
export const allowsDirection = (filter: TrafficDirection, direction = 1) => filter === 'both' || (filter === 'sent' ? direction === 1 : direction === -1)

export function endpointLocation(endpoint: MapEndpoint): Pick<LocationTraffic, 'id' | 'label' | 'detail' | 'position' | 'country'> | null {
  const country = countryFootprint(endpoint)
  if (country) return { id: `country:${country.code}`, label: country.name, detail: 'Country estimate · city unknown', country, ...(hasMapCoordinates(country.position[1], country.position[0]) ? { position: country.position } : {}) }
  if (!hasMapCoordinates(endpoint.position[1], endpoint.position[0])) return null
  return { id: endpoint.position.join(','), label: endpoint.city || endpoint.country || endpoint.label, detail: [endpoint.city ? endpoint.country : '', 'Approximate IP location'].filter(Boolean).join(' · '), position: endpoint.position }
}
const zero = (): ByteTotals => ({ received: 0, sent: 0, partial: false })
function add(target: ByteTotals, value: ByteTotals) { target.received += value.received; target.sent += value.sent; target.partial ||= value.partial }

/** One aggregate series, one versioned location. Unlocated traffic participates in totals and timeline. */
export function projectWorkspace(catalog: MapTrackCatalog, scene: MapTimelineScene, index: DestinationVolumeIndex, cursor: number, state: WorkspaceState) {
  const all = projectMapTracks(catalog, scene, cursor, index)
  const byEndpoint = new Map(scene.endpoints.filter(e => e.availableFromMs <= cursor).map(e => [e.id, endpointLocation(e)]))
  const locations = new Map<string, LocationTraffic>()
  const rows = new Map<string, TimelineTrafficRow>()
  const bySeries = new Map<string, MapSeries>()
  const total = zero()
  const volumeBySeries = new Map<string, ByteTotals>()
  for (const series of all.bySeries.values()) {
    const location = byEndpoint.get(series.id) ?? { id: 'unlocated', label: 'Unlocated', detail: 'Included in totals · no map position' }
    const volume = seriesVolume(series, index, cursor)
    volumeBySeries.set(series.id, volume)
    const group = locations.get(location.id) ?? { ...location, ...zero(), bytes: 0, series: [] }
    add(group, volume); group.series.push(series); group.bytes = directionalBytes(group, state.direction)
    locations.set(group.id, group)
    if (state.locationId && state.locationId !== location.id) continue
    add(total, volume)
    // Known zero-byte directions are hidden; incomplete capture remains visible.
    if (state.direction !== 'both' && volume[state.direction] === 0 && !volume.partial) continue
    const scoped = { ...series, bytes: directionalBytes(volume, state.direction) }
    bySeries.set(series.id, scoped)
    const id = JSON.stringify([series.trackId, location.id])
    const row = rows.get(id) ?? { id, trackId: series.trackId, label: series.label, client: series.client, location: location.label, locationId: location.id, ...zero(), bytes: 0, series: [] }
    add(row, volume); row.bytes = directionalBytes(row, state.direction); row.series.push(scoped); rows.set(id, row)
  }
  const tracks: MapTrack[] = all.tracks.map(track => {
    const series = track.series.flatMap(c => bySeries.has(c.id) ? [bySeries.get(c.id)!] : [])
    return { ...track, series, bytes: series.reduce((sum, c) => sum + c.bytes, 0), activeCount: series.filter(c => c.active).length, mappedCount: series.filter(c => c.mapped).length }
  }).filter(track => track.series.length).sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id))
  return { locations: [...locations.values()].filter(location => state.direction === 'both' || location.bytes > 0 || location.partial).sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id)), rows: [...rows.values()].sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id)), total, bySeries, tracks, volumeBySeries, scene: sceneForTracks(scene, bySeries) }
}
export type WorkspaceProjection = ReturnType<typeof projectWorkspace>
