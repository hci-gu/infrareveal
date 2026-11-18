import type { ByteTotals } from './destinationVolumes'
import type { MapSeries } from './mapTracks'

export type DirectionPoint = { id: string; label: string; sent: number; received: number; clients: number }

/** Directional bytes per service across devices: the same site on two phones is
 * one point. Only services with traffic in both the window and filters appear. */
export function directionPoints(series: Iterable<MapSeries>, volumes: ReadonlyMap<string, ByteTotals>): DirectionPoint[] {
  const services = new Map<string, DirectionPoint & { clientSet: Set<string> }>()
  for (const item of series) {
    const volume = volumes.get(item.id)
    if (!volume || volume.sent + volume.received <= 0) continue
    const id = item.site || item.label
    const point = services.get(id) ?? { id, label: item.label || item.site, sent: 0, received: 0, clients: 0, clientSet: new Set<string>() }
    point.sent += volume.sent
    point.received += volume.received
    point.clientSet.add(item.client)
    services.set(id, point)
  }
  return [...services.values()].map(({ clientSet, ...point }) => ({ ...point, clients: clientSet.size }))
    .sort((a, b) => (b.sent + b.received) - (a.sent + a.received) || a.label.localeCompare(b.label))
}

/** How many times more one direction carried. Infinity when the other is zero. */
export const sendRatio = (point: Pick<DirectionPoint, 'sent' | 'received'>) => point.received > 0 ? point.sent / point.received : Infinity

/** A shared power-of-ten domain for both axes, so the diagonal is sent = received. */
export function logDomain(points: readonly DirectionPoint[]): [number, number] {
  const values = points.flatMap(point => [point.sent, point.received]).filter(value => value > 0)
  if (!values.length) return [100, 1_000_000]
  const lo = Math.max(10, 10 ** Math.floor(Math.log10(Math.min(...values))))
  const hi = 10 ** Math.ceil(Math.log10(Math.max(...values)))
  return [lo, Math.max(hi, lo * 100)]
}

/** Compact power-of-ten tick labels: 100 B, 1 kB, 10 kB, 1 MB… */
export function tickLabel(bytes: number) {
  const units: [number, string][] = [[1e9, 'GB'], [1e6, 'MB'], [1e3, 'kB']]
  for (const [scale, unit] of units) if (bytes >= scale) return `${Math.round(bytes / scale)} ${unit}`
  return `${Math.round(bytes)} B`
}
