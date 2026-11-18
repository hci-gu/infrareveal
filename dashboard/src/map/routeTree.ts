import { routeForSeriesAt } from '@infrareveal/session-state'
import type { RouteEvidence, RouteHop } from '@infrareveal/session-state'
import type { GatewayOrigin, MapPosition } from './mapModel'
import type { LocationTraffic } from './mapWorkspace'
import type { ByteTotals } from './destinationVolumes'
import { hasMapCoordinates } from './mapCoordinates'

/** Hops in the same ~half-degree cell are drawn as one waypoint (roughly one metro area). */
const CELL_DEGREES = 0.5
/** Country-level hop geography would pull trunks to arbitrary centroids. */
const MAX_HOP_ACCURACY_KM = 500

export type RouteTreeEdge = {
  id: string
  /** `route`: between measured waypoints. `direct`: no measured path covers this part. */
  kind: 'route' | 'direct'
  from: MapPosition
  to: MapPosition
  received: number
  sent: number
  locationIds: string[]
  trackIds: string[]
}
export type RouteTreeNode = { id: string; position: MapPosition; received: number; sent: number; label: string; routers: number }
export type RouteTree = { edges: RouteTreeEdge[]; nodes: RouteTreeNode[]; peak: number; measured: number; total: number }

type Waypoint = { key: string; position: MapPosition; hop?: RouteHop }

export function hopPosition(hop: RouteHop): MapPosition | null {
  if (hop.missing || (hop.accuracy_km ?? 0) > MAX_HOP_ACCURACY_KM) return null
  if (hop.lat !== undefined && hop.lon !== undefined && hasMapCoordinates(hop.lat, hop.lon)) return [hop.lon, hop.lat]
  const evidence = hop.interface_evidence ?? {}
  const geo = evidence[hop.address]?.geo ?? Object.values(evidence).find(value => value.geo)?.geo
  if (!geo || (geo.accuracy_km ?? 0) > MAX_HOP_ACCURACY_KM || !hasMapCoordinates(geo.lat, geo.lon)) return null
  return [geo.lon, geo.lat]
}

const cellKey = ([lon, lat]: MapPosition) => `cell:${Math.round(lat / CELL_DEGREES)},${Math.round(lon / CELL_DEGREES)}`

/**
 * Merge each located series' measured route into one flow network rooted at the gateway.
 * Segments shared by several routes accumulate their traffic, so trunks show common
 * upstream paths. Series without a usable route keep a direct gateway → destination edge.
 */
export function buildRouteTree(locations: LocationTraffic[], routes: readonly RouteEvidence[], origin: GatewayOrigin, volumeBySeries: Map<string, ByteTotals>, cursorMs: number): RouteTree {
  const originPosition: MapPosition = [origin.longitude, origin.latitude]
  const originKey = cellKey(originPosition)
  const edges = new Map<string, RouteTreeEdge & { locations: Set<string>; tracks: Set<string> }>()
  const hopCells = new Map<string, { positions: Map<string, MapPosition>; received: number; sent: number; labels: Map<string, number>; routers: Set<string> }>()
  let measured = 0, total = 0
  const addEdge = (kind: RouteTreeEdge['kind'], from: Waypoint, to: Waypoint, volume: ByteTotals, locationId: string, trackId: string) => {
    const id = `${kind}:${from.key}>${to.key}`
    const edge = edges.get(id) ?? { id, kind, from: from.position, to: to.position, received: 0, sent: 0, locationIds: [], trackIds: [], locations: new Set(), tracks: new Set() }
    edge.received += volume.received; edge.sent += volume.sent
    edge.locations.add(locationId); edge.tracks.add(trackId)
    edges.set(id, edge)
  }
  for (const location of locations) {
    if (!location.position || !hasMapCoordinates(location.position[1], location.position[0])) continue
    const destination: Waypoint = { key: `loc:${location.id}`, position: location.position }
    for (const series of location.series) {
      const volume = volumeBySeries.get(series.id)
      if (!volume || volume.received + volume.sent <= 0) continue
      total += volume.received + volume.sent
      const route = series.chunks[0] ? routeForSeriesAt(series.chunks[0], routes, cursorMs) : null
      const path: Waypoint[] = [{ key: originKey, position: originPosition }]
      for (const hop of route?.hops ?? []) {
        const position = hopPosition(hop)
        if (!position) continue
        const key = cellKey(position)
        const seen = path.findIndex(point => point.key === key)
        // Geolocation noise can make a path revisit a cell; cut the loop out.
        if (seen >= 0) { path.length = seen + 1; continue }
        path.push({ key, position, hop })
      }
      // The destination replaces a final hop in its own cell so the trunk ends on its marker.
      if (path.length > 1 && path[path.length - 1].key === cellKey(destination.position)) path.pop()
      const hops = path.slice(1)
      if (hops.length) measured += volume.received + volume.sent
      for (const point of hops) {
        const cell = hopCells.get(point.key) ?? { positions: new Map(), received: 0, sent: 0, labels: new Map(), routers: new Set() }
        cell.positions.set(point.position.join(','), point.position)
        cell.received += volume.received; cell.sent += volume.sent
        const label = [point.hop?.city, point.hop?.country].filter(Boolean).join(', ') || point.hop?.hostname || ''
        if (label) cell.labels.set(label, (cell.labels.get(label) ?? 0) + volume.received + volume.sent)
        if (point.hop?.address) cell.routers.add(point.hop.address)
        hopCells.set(point.key, cell)
      }
      for (let i = 1; i < path.length; i++) addEdge('route', path[i - 1], path[i], volume, location.id, series.trackId)
      addEdge(hops.length && route?.destination_reached ? 'route' : 'direct', path[path.length - 1], destination, volume, location.id, series.trackId)
    }
  }
  // Waypoints sit at the mean of their members so a cell's position does not depend on arrival order.
  const cellPositions = new Map([...hopCells].map(([key, cell]) => {
    const positions = [...cell.positions.values()]
    return [key, [positions.reduce((sum, p) => sum + p[0], 0) / positions.length, positions.reduce((sum, p) => sum + p[1], 0) / positions.length] as MapPosition]
  }))
  const resultEdges = [...edges.values()].map(({ locations: locationSet, tracks, ...edge }) => {
    const [fromKey, toKey] = edge.id.slice(edge.id.indexOf(':') + 1).split('>')
    return { ...edge, from: cellPositions.get(fromKey) ?? edge.from, to: cellPositions.get(toKey) ?? edge.to, locationIds: [...locationSet].sort(), trackIds: [...tracks].sort() }
  }).sort((a, b) => (b.received + b.sent) - (a.received + a.sent) || a.id.localeCompare(b.id))
  const nodes = [...hopCells].map(([id, cell]) => ({
    id, position: cellPositions.get(id)!, received: cell.received, sent: cell.sent, routers: cell.routers.size,
    label: [...cell.labels].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]))[0]?.[0] ?? 'Network hop',
  })).sort((a, b) => a.id.localeCompare(b.id))
  return { edges: resultEdges, nodes, peak: Math.max(0, ...resultEdges.map(edge => edge.received + edge.sent)), measured, total }
}
