import { colorCSS, TrackColors } from './mapTracks'
import type { MapSeries, MapTrack } from './mapTracks'

export const SHARE_SLICES = 5
export type ShareItem = { id: string; label: string; detail: string; bytes: number; color: string }
export type Share = Omit<ShareItem, 'color'> & { share: number; color: string | null; count: number }
export type ShareBreakdown = { total: number; shares: Share[] }

/** The largest parts keep their color; the tail folds into one neutral "Other"
 * slice, so the chart never needs more hues than it can tell apart. */
export function shareBreakdown(items: readonly ShareItem[], slices = SHARE_SLICES, unit = 'items'): ShareBreakdown {
  const ranked = items.filter(item => item.bytes > 0).sort((a, b) => b.bytes - a.bytes || a.label.localeCompare(b.label) || a.id.localeCompare(b.id))
  const total = ranked.reduce((sum, item) => sum + item.bytes, 0)
  if (!total) return { total: 0, shares: [] }
  const head = ranked.length > slices + 1 ? ranked.slice(0, slices) : ranked
  const shares: Share[] = head.map(item => ({ ...item, share: item.bytes / total, count: 1 }))
  const tail = ranked.slice(head.length)
  if (tail.length) {
    const bytes = tail.reduce((sum, item) => sum + item.bytes, 0)
    shares.push({ id: 'other', label: 'Other', detail: `${tail.length} ${unit}`, bytes, share: bytes / total, color: null, count: tail.length })
  }
  return { total, shares }
}

/** Tracks reuse their map and Tracks-list color. */
export const trackShares = (tracks: readonly MapTrack[], slices = SHARE_SLICES) =>
  shareBreakdown(tracks.map(track => ({ id: track.id, label: track.label, detail: track.client, bytes: track.bytes, color: colorCSS(track.color) })), slices, 'tracks')

export const UNKNOWN_COUNTRY = 'unknown'

/** Filtered endpoint bytes by destination country. `colors` keeps each
 * country's hue stable while live ranks change. */
export function countryShares(series: Iterable<MapSeries>, colors: TrackColors, slices = SHARE_SLICES): ShareBreakdown {
  const countries = new Map<string, ShareItem & { endpoints: number }>()
  for (const item of series) {
    const id = item.country || UNKNOWN_COUNTRY
    const country = countries.get(id) ?? { id, label: item.country || 'Unknown location', detail: '', bytes: 0, color: '', endpoints: 0 }
    country.bytes += item.bytes
    country.endpoints += 1
    countries.set(id, country)
  }
  return shareBreakdown([...countries.values()].map(country => ({ ...country, detail: `${country.endpoints} ${country.endpoints === 1 ? 'endpoint' : 'endpoints'}`, color: colorCSS(colors.get(country.id)) })), slices, 'countries')
}
