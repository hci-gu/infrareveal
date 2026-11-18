import { expect, it } from 'vitest'
import { directionPoints, logDomain, sendRatio, tickLabel } from './directionPoints'
import type { MapSeries } from './mapTracks'

const series = (id: string, site: string, client: string) => ({ id, site, label: site, client }) as MapSeries

it('sums directional bytes per service across devices and skips series outside the window', () => {
  const volumes = new Map([['a', { sent: 10, received: 100, partial: false }], ['b', { sent: 5, received: 50, partial: false }], ['c', { sent: 900, received: 30, partial: false }]])
  const points = directionPoints([series('a', 'svt.se', '10.0.0.2'), series('b', 'svt.se', '10.0.0.3'), series('c', 'tracker.example', '10.0.0.2'), series('d', 'idle.example', '10.0.0.2')], volumes)
  expect(points).toEqual([
    { id: 'tracker.example', label: 'tracker.example', sent: 900, received: 30, clients: 1 },
    { id: 'svt.se', label: 'svt.se', sent: 15, received: 150, clients: 2 },
  ])
  expect(sendRatio(points[0])).toBe(30)
  expect(sendRatio({ sent: 5, received: 0 })).toBe(Infinity)
})

it('shares one power-of-ten domain across both axes', () => {
  expect(logDomain([{ id: 'a', label: 'a', sent: 0, received: 4_200, clients: 1 }, { id: 'b', label: 'b', sent: 380, received: 2_100_000, clients: 1 }])).toEqual([100, 10_000_000])
  expect(logDomain([])).toEqual([100, 1_000_000])
  expect([100, 1_000, 10_000, 1_000_000].map(tickLabel)).toEqual(['100 B', '1 kB', '10 kB', '1 MB'])
})
