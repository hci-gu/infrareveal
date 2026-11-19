import type { MapPosition } from './mapModel'

/**
 * Mercator and Equal Earth render through the same deck.gl Web Mercator view;
 * the globe uses deck.gl's (experimental) GlobeView with real coordinates.
 *
 * Equal Earth is drawn by handing deck.gl substitute ("Mercator-space")
 * coordinates: each geographic position is projected to Equal Earth, and that
 * planar point is inverted through Web Mercator. deck.gl's own projection then
 * lands every vertex exactly where Equal Earth places it, so layers, shaders,
 * picking, labels and camera controls work unchanged. Straight segments in the
 * substitute space are straight in Equal Earth, so arcs must not follow great
 * circles there, and map tiles (pre-rendered in Mercator) cannot be used.
 */
export type MapProjectionId = 'mercator' | 'equal-earth' | 'globe'
export type MapProjection = {
  id: MapProjectionId
  label: string
  /** Geographic [lon, lat] → the [lon, lat] deck.gl should draw. */
  toMap: (position: MapPosition) => MapPosition
  /** Arcs follow great circles (true geography) rather than straight map lines. */
  greatCircle: boolean
  /** Longitudes wrap at the antimeridian (Mercator only; Equal Earth has edges). */
  wrap: boolean
  /** Online basemap tiles exist only in Web Mercator. */
  tiles: boolean
  graticule: MapPosition[][]
  /** The world's outline in map coordinates, or null when the map is unbounded. */
  outline: MapPosition[] | null
  /** Drawn on a 3D sphere (deck.gl GlobeView): depth hides the far side, there is no tilt. */
  globe: boolean
}

const identity = (position: MapPosition) => position

const A1 = 1.340264, A2 = -0.081106, A3 = 0.000893, A4 = 0.003796
const M = Math.sqrt(3) / 2
/** Half the projected width of the world, used to fill Mercator's ±180° span. */
const EQUAL_EARTH_X_MAX = Math.PI / (M * A1)

/** Equal Earth (Šavrič, Patterson & Jenny 2018) in unit-sphere radians. */
export function equalEarthPlanar([longitude, latitude]: MapPosition): MapPosition {
  const theta = Math.asin(M * Math.sin(Math.max(-90, Math.min(90, latitude)) * Math.PI / 180))
  const t2 = theta * theta, t6 = t2 * t2 * t2
  const x = longitude * Math.PI / 180 * Math.cos(theta) / (M * (A1 + 3 * A2 * t2 + t6 * (7 * A3 + 9 * A4 * t2)))
  const y = theta * (A1 + A2 * t2 + t6 * (A3 + A4 * t2))
  return [x, y]
}

/** Equal Earth → substitute coordinates rendered correctly by a Web Mercator view. */
export function equalEarthToMercator(position: MapPosition): MapPosition {
  const [x, y] = equalEarthPlanar(position)
  const scale = Math.PI / EQUAL_EARTH_X_MAX
  return [x * scale * 180 / Math.PI, (2 * Math.atan(Math.exp(y * scale)) - Math.PI / 2) * 180 / Math.PI]
}

function line(from: MapPosition, to: MapPosition, steps: number): MapPosition[] {
  return Array.from({ length: steps + 1 }, (_, i) => [from[0] + (to[0] - from[0]) * i / steps, from[1] + (to[1] - from[1]) * i / steps])
}
function graticule(maxLatitude: number): MapPosition[][] {
  return [
    ...Array.from({ length: 13 }, (_, i) => line([-180 + i * 30, -maxLatitude], [-180 + i * 30, maxLatitude], 60)),
    ...Array.from({ length: 5 }, (_, i) => line([-180, -60 + i * 30], [180, -60 + i * 30], 72)),
  ]
}

export const MERCATOR: MapProjection = {
  id: 'mercator', label: 'Mercator', toMap: identity, greatCircle: true, wrap: true, tiles: true,
  graticule: graticule(80), outline: null, globe: false,
}

export const EQUAL_EARTH: MapProjection = {
  id: 'equal-earth', label: 'Equal Earth', toMap: equalEarthToMercator, greatCircle: false, wrap: false, tiles: false,
  graticule: graticule(90).map(path => path.map(equalEarthToMercator)),
  outline: [...line([-180, -90], [-180, 90], 90), ...line([180, 90], [180, -90], 90)].map(equalEarthToMercator),
  globe: false,
}

/**
 * Real longitude/latitude on a sphere. deck.gl subdivides paths and polygons
 * along great circles at the view's resolution, so no substitute coordinates,
 * antimeridian wrapping or manual densifying is needed. No tiles: the bundled
 * Natural Earth outlines are the basemap, as for Equal Earth.
 */
export const GLOBE: MapProjection = {
  id: 'globe', label: 'Globe', toMap: identity, greatCircle: true, wrap: false, tiles: false,
  graticule: graticule(90), outline: null, globe: true,
}

export const mapProjection = (id: MapProjectionId) => id === 'equal-earth' ? EQUAL_EARTH : id === 'globe' ? GLOBE : MERCATOR
