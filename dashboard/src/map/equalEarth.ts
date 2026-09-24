import type { MapPosition } from './mapModel'

/** Equal Earth forward projection, radians to a 1000 × 560 world overview. */
export function equalEarth([longitude, latitude]: MapPosition): MapPosition {
  const theta = Math.asin(Math.sqrt(3) / 2 * Math.sin(Math.max(-90, Math.min(90, latitude)) * Math.PI / 180))
  const squared = theta * theta
  const y = theta * (1.340264 - .081106 * squared + .000893 * squared ** 3 + .003796 * squared ** 4)
  const divisor = Math.sqrt(3) / 2 * (1.340264 - .243318 * squared + .006251 * squared ** 3 + .034164 * squared ** 4)
  return [500 + 178 * longitude * Math.PI / 180 * Math.cos(theta) / divisor, 280 - 178 * y]
}
export function equalEarthPath(points: MapPosition[], close = false): string {
  return points.map((point, index) => { const [x, y] = equalEarth(point); return `${index ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}` }).join('') + (close ? 'Z' : '')
}
