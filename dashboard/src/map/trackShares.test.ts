import { expect, it } from 'vitest'
import { countryShares, trackShares } from './trackShares'
import { TrackColors } from './mapTracks'
import type { MapSeries, MapTrack } from './mapTracks'

const track = (id: string, bytes: number): MapTrack => ({ id, label: id, client: '10.0.0.2', site: id, color: [1, 2, 3], series: [], lastActivityMs: 0, bytes, mappedCount: 0 })

it('ranks tracks by bytes and folds the tail into a neutral Other slice', () => {
  const { total, shares } = trackShares([track('a', 10), track('b', 50), track('c', 0), track('d', 20), track('e', 5), track('f', 5), track('g', 5), track('h', 5)])
  expect(total).toBe(100)
  expect(shares.map(share => share.id)).toEqual(['b', 'd', 'a', 'e', 'f', 'other'])
  expect(shares[shares.length - 1]).toMatchObject({ label: 'Other', bytes: 10, count: 2, color: null })
  expect(shares.reduce((sum, share) => sum + share.share, 0)).toBeCloseTo(1)
  expect(shares[0].color).toBe('rgb(1 2 3)')
})
it('never folds a single track into Other, and is empty without traffic', () => {
  expect(trackShares(['a', 'b', 'c', 'd', 'e', 'f'].map(id => track(id, 1))).shares.some(share => share.id === 'other')).toBe(false)
  expect(trackShares([track('a', 0)])).toEqual({ total: 0, shares: [] })
})
it('sums endpoint bytes per destination country with stable hues and an explicit unknown', () => {
  const series = (id: string, country: string, bytes: number) => ({ id, country, bytes }) as MapSeries
  const colors = new TrackColors()
  const first = countryShares([series('a', 'Sweden', 30), series('b', 'Denmark', 50), series('c', 'Sweden', 40), series('d', '', 10)], colors)
  expect(first.total).toBe(130)
  expect(first.shares.map(share => [share.label, share.bytes, share.detail])).toEqual([['Sweden', 70, '2 endpoints'], ['Denmark', 50, '1 endpoint'], ['Unknown location', 10, '1 endpoint']])
  const sweden = first.shares[0].color
  // Rank changes must not repaint a country.
  const second = countryShares([series('b', 'Denmark', 500), series('a', 'Sweden', 1)], colors)
  expect(second.shares.find(share => share.label === 'Sweden')!.color).toBe(sweden)
})
