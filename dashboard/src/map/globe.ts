import type { MapPosition } from './mapModel'

/** Geometry helpers for the globe projection (positions are [lon, lat] degrees). */
export function unitVector([lon, lat]: readonly number[]): [number, number, number] {
  const rad = Math.PI / 180, cosLat = Math.cos(lat * rad)
  return [cosLat * Math.cos(lon * rad), cosLat * Math.sin(lon * rad), Math.sin(lat * rad)]
}
const dot = (a: readonly number[], b: readonly number[]) => a[0] * b[0] + a[1] * b[1] + a[2] * b[2]

/** Angle between two positions as seen from the centre of the Earth, in degrees. */
export function angularDistance(a: MapPosition, b: MapPosition) {
  return Math.acos(Math.max(-1, Math.min(1, dot(unitVector(a), unitVector(b))))) * 180 / Math.PI
}

/**
 * Whether a position is on the visible side of a globe viewed from above
 * `center`. The camera sits a finite distance away, so slightly less than a
 * hemisphere is visible; the margin also keeps labels off the very rim.
 */
export function facesCamera(center: MapPosition, position: readonly number[], margin = 0.15) {
  return dot(unitVector(center), unitVector(position)) > margin
}

/** The point on the sphere nearest to the average of the positions' directions. */
export function sphericalCentroid(positions: readonly MapPosition[]): MapPosition {
  const sum = positions.reduce((total, position) => { const v = unitVector(position); return [total[0] + v[0], total[1] + v[1], total[2] + v[2]] }, [0, 0, 0])
  const length = Math.hypot(sum[0], sum[1], sum[2])
  if (length < 1e-9) return positions[0] ?? [0, 0]
  return [Math.atan2(sum[1], sum[0]) * 180 / Math.PI, Math.asin(sum[2] / length) * 180 / Math.PI]
}

/** Idle rotation speed of the globe, degrees of longitude per second. */
export const GLOBE_SPIN_DEGREES_PER_SECOND = 4
/** Spinning resumes this long after the last interaction. */
export const GLOBE_SPIN_IDLE_MS = 6000

/** The position reached travelling `distance` degrees along a great circle from `from`, at `bearing` degrees from north. */
export function destinationPoint([lon, lat]: MapPosition, bearing: number, distance: number): MapPosition {
  const rad = Math.PI / 180, δ = distance * rad, θ = bearing * rad, φ1 = lat * rad, λ1 = lon * rad
  const φ2 = Math.asin(Math.sin(φ1) * Math.cos(δ) + Math.cos(φ1) * Math.sin(δ) * Math.cos(θ))
  const λ2 = λ1 + Math.atan2(Math.sin(θ) * Math.sin(δ) * Math.cos(φ1), Math.cos(δ) - Math.sin(φ1) * Math.sin(φ2))
  return [((λ2 / rad + 540) % 360) - 180, φ2 / rad]
}

/**
 * The globe's outline on screen: its centre and the largest distance of a
 * visible point from it. Points on the rim sit a little under 90° from the
 * view centre because the camera is a finite distance away.
 */
export function globeOutline(project: (position: MapPosition) => number[], center: MapPosition): { center: [number, number]; radius: number } {
  const [cx, cy] = project(center)
  let radius = 0
  for (let distance = 70; distance <= 90; distance += 1) {
    const [x, y] = project(destinationPoint(center, 90, distance))
    radius = Math.max(radius, Math.hypot(x - cx, y - cy))
  }
  return { center: [cx, cy], radius }
}
