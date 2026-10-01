import { BitmapLayer, TextLayer } from '@deck.gl/layers'
import { WebMercatorViewport } from '@deck.gl/core'
import countries from './data/countries.json'
import type { MapPosition } from './mapModel'

const projection = new WebMercatorViewport({ width: 1, height: 1, longitude: 0, latitude: 0, zoom: 0 })
// The map projection is fixed. Project static geography once, instead of running
// logarithms/trigonometry for thousands of vertices on every animation frame.
function project(position: number[]): MapPosition {
  const [x, y] = projection.projectPosition([position[0], Math.max(-89.9, Math.min(89.9, position[1]))])
  return [x, y]
}
const land = countries.flatMap(country => country.polygons.map(polygon => ({ polygon: polygon.map(ring => ring.map(project)) })))
// At world scale only large labels fit; higher zoom reveals the smaller countries.
const names = countries.map(country => ({ ...country, position: project(country.position), extent: Math.max(...country.polygons.map(polygon => {
  const xs = polygon[0].map(p => p[0]), ys = polygon[0].map(p => p[1])
  return (Math.max(...xs) - Math.min(...xs)) * (Math.max(...ys) - Math.min(...ys))
})) }))

type Bounds = [number, number, number, number]
let paths: Path2D[] | undefined
let cached: { theme: string; detail: number; bounds: Bounds; canvas: HTMLCanvasElement } | undefined

/** Cache static geography as one texture. Zoomed views rasterize a fresh, padded
 * region, retaining coastline detail without painting all polygons every frame. */
function geography(theme: 'dark' | 'light', viewport: WebMercatorViewport) {
  const detail = Math.max(0, Math.floor(viewport.zoom) - 2)
  const [west, south, east, north] = viewport.getBounds()
  const [left, bottom] = project([west, south]), [right, top] = project([east, north])
  if (cached?.theme === theme && cached.detail === detail && (detail === 0 ||
    (left >= cached.bounds[0] && bottom >= cached.bounds[1] && right <= cached.bounds[2] && top <= cached.bounds[3]))) return cached
  const dx = Math.max(1e-6, right - left), dy = Math.max(1e-6, top - bottom)
  const bounds: Bounds = detail === 0 ? [0, 0, 512, 512] : [left - dx / 2, bottom - dy / 2, right + dx / 2, top + dy / 2]
  const canvas = document.createElement('canvas')
  canvas.width = canvas.height = detail === 0 ? 2048 : 4096
  const context = canvas.getContext('2d')!
  const light = theme === 'light'
  context.fillStyle = light ? '#edf3ef' : '#101f28'
  context.fillRect(0, 0, canvas.width, canvas.height)
  const sx = canvas.width / (bounds[2] - bounds[0]), sy = canvas.height / (bounds[3] - bounds[1])
  context.setTransform(sx, 0, 0, -sy, -bounds[0] * sx, bounds[3] * sy)
  paths ??= land.map(({ polygon }) => {
    const path = new Path2D()
    for (const ring of polygon) {
      ring.forEach(([x, y], i) => i === 0 ? path.moveTo(x, y) : path.lineTo(x, y))
      path.closePath()
    }
    return path
  })
  context.fillStyle = light ? '#d2e0d8' : '#213a43'
  for (const path of paths) context.fill(path, 'evenodd')
  context.strokeStyle = light ? '#a6bbb3' : '#3b5660'
  context.lineWidth = .5 / 2 ** Math.floor(viewport.zoom)
  context.lineJoin = 'round'
  for (const path of paths) context.stroke(path)
  cached = { theme, detail, bounds, canvas }
  return cached
}

/** Local cached geography and crisp labels, with one WebGL context and no tiles. */
export function bundledBasemap(theme: 'dark' | 'light', labels: boolean, viewport: WebMercatorViewport) {
  const light = theme === 'light'
  const { canvas, bounds } = geography(theme, viewport)
  return [
    new BitmapLayer({ id: 'base-geography', coordinateSystem: 'cartesian', image: canvas, bounds, pickable: false }),
    new TextLayer({ id: 'base-labels', coordinateSystem: 'cartesian', data: names.filter(country => country.extent > 120 / 2 ** Math.max(0, Math.floor(viewport.zoom) - 1)),
      visible: labels, getPosition: country => country.position as MapPosition, getText: country => country.name.toUpperCase(),
      getSize: 10, getColor: light ? [88, 117, 119] : [125, 151, 160], fontFamily: 'system-ui, sans-serif',
      fontWeight: 500, pickable: false, parameters: { depthCompare: 'always', depthWriteEnabled: false } }),
  ]
}
