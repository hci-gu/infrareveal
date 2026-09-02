import type { Destination, Flow, GatewayData, Route } from '@infrareveal/session-state'
import { parseEpoch } from '@infrareveal/session-state'

export type MapPosition = [longitude: number, latitude: number]

export type GatewayOrigin = {
  latitude: number
  longitude: number
  label: string
}

export type MapFlowInterval = {
  id: string
  startMs: number
  endMs: number
  bytes: number
  packets: number
}

export type MapRoutePath = {
  id: string
  completedAtMs: number
  positions: MapPosition[]
}

export type MapEndpoint = {
  id: string
  ip: string
  label: string
  provider: string
  city: string
  country: string
  position: MapPosition
  availableFromMs: number
  firstSeenMs: number
  lastSeenMs: number
  flows: MapFlowInterval[]
  routes: MapRoutePath[]
}

export type MapTimelineScene = {
  sessionId: string | null
  sessionName: string
  startMs: number
  endMs: number
  origin: GatewayOrigin
  endpoints: MapEndpoint[]
  totalFlowCount: number
}

export type MapPoint = {
  id: string
  ip: string
  label: string
  provider: string
  location: string
  position: MapPosition
  flowCount: number
  activeFlowCount: number
  bytes: number
}

export type MapArc = {
  id: string
  sourcePosition: MapPosition
  targetPosition: MapPosition
  activeFlowCount: number
  bytes: number
  tilt: number
}

export type MapFrame = {
  points: MapPoint[]
  arcs: MapArc[]
  seenFlowCount: number
  activeFlowCount: number
  byteCount: number
}

const ACTIVE_TRAIL_MS = 5_000
const MAX_ARC_SEGMENTS = 4_000

/** Builds a compact, serializable model once per overview revision. */
export function buildMapTimelineScene(data: GatewayData, origin: GatewayOrigin, canonicalStartMs?: number): MapTimelineScene {
  const session = data.selectedSession
  const sessionStartMs = Number.isFinite(canonicalStartMs)
    ? canonicalStartMs!
    : parseEpoch(session?.started_at || session?.created, 0)
  const destinationsByIP = new Map(
    data.destinations
      .filter(hasCoordinates)
      .map((destination) => [destination.ip, destination]),
  )
  const routesBySocket = indexRoutes(data.routes, origin, destinationsByIP)
  const flowsByDestination = new Map<string, MapFlowInterval[]>()
  const routesByDestination = new Map<string, Map<string, MapRoutePath>>()

  for (const flow of data.flows) {
    if (!destinationsByIP.has(flow.destination_ip)) continue
    const interval = mapFlow(flow, sessionStartMs)
    if (!interval) continue
    const flows = flowsByDestination.get(flow.destination_ip)
    if (flows) flows.push(interval)
    else flowsByDestination.set(flow.destination_ip, [interval])

    const paths = routesBySocket.get(socketKey(flow.destination_ip, flow.destination_port, flow.protocol)) ?? []
    if (paths.length > 0) {
      const destinationRoutes = routesByDestination.get(flow.destination_ip) ?? new Map<string, MapRoutePath>()
      for (const path of paths) destinationRoutes.set(path.id, path)
      routesByDestination.set(flow.destination_ip, destinationRoutes)
    }
  }

  const endpoints: MapEndpoint[] = []
  for (const [ip, flows] of flowsByDestination) {
    const destination = destinationsByIP.get(ip)
    if (!destination) continue
    flows.sort((left, right) => left.startMs - right.startMs || left.id.localeCompare(right.id))
    const firstSeenMs = flows[0]?.startMs ?? sessionStartMs
    const lastSeenMs = flows.reduce((latest, flow) => Math.max(latest, flow.endMs), firstSeenMs)
    const destinationCreatedMs = parseEpoch(destination.created, firstSeenMs)
    const routes = Array.from(routesByDestination.get(ip)?.values() ?? []).sort((left, right) =>
      left.completedAtMs - right.completedAtMs || left.id.localeCompare(right.id),
    )

    endpoints.push({
      id: destination.id || ip,
      ip,
      label: endpointLabel(destination),
      provider: destination.provider_label || destination.organization || '',
      city: destination.city || '',
      country: destination.country || '',
      position: [destination.lon, destination.lat],
      availableFromMs: Math.max(firstSeenMs, destinationCreatedMs),
      firstSeenMs,
      lastSeenMs,
      flows,
      routes,
    })
  }

  endpoints.sort((left, right) => left.firstSeenMs - right.firstSeenMs || left.ip.localeCompare(right.ip))
  const lastFlowMs = endpoints.reduce((latest, endpoint) => Math.max(latest, endpoint.lastSeenMs), sessionStartMs)
  const sessionEndMs = parseEpoch(session?.ended_at, lastFlowMs)

  return {
    sessionId: session?.id ?? null,
    sessionName: session?.name || 'InfraReveal session',
    startMs: sessionStartMs,
    endMs: Math.max(sessionStartMs, sessionEndMs, lastFlowMs),
    origin,
    endpoints,
    totalFlowCount: data.flows.length,
  }
}

/** Selects only what can be known and shown at the current session time. */
export function projectMapFrame(
  scene: MapTimelineScene,
  cursorMs: number,
  activeTrailMs = ACTIVE_TRAIL_MS,
  maximumArcSegments = MAX_ARC_SEGMENTS,
): MapFrame {
  const points: MapPoint[] = []
  const activeEndpoints: Array<{ endpoint: MapEndpoint; point: MapPoint; route: MapPosition[] }> = []
  let seenFlowCount = 0
  let activeFlowCount = 0
  let byteCount = 0

  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > cursorMs || endpoint.firstSeenMs > cursorMs) continue
    let endpointSeenFlows = 0
    let endpointActiveFlows = 0
    let endpointBytes = 0

    for (const flow of endpoint.flows) {
      if (flow.startMs > cursorMs) break
      endpointSeenFlows += 1
      endpointBytes += flow.bytes
      if (cursorMs <= flow.endMs + activeTrailMs) endpointActiveFlows += 1
    }
    if (endpointSeenFlows === 0) continue

    const point: MapPoint = {
      id: endpoint.id,
      ip: endpoint.ip,
      label: endpoint.label,
      provider: endpoint.provider,
      location: [endpoint.city, endpoint.country].filter(Boolean).join(', '),
      position: endpoint.position,
      flowCount: endpointSeenFlows,
      activeFlowCount: endpointActiveFlows,
      bytes: endpointBytes,
    }
    points.push(point)
    seenFlowCount += endpointSeenFlows
    activeFlowCount += endpointActiveFlows
    byteCount += endpointBytes

    if (endpointActiveFlows > 0) {
      activeEndpoints.push({
        endpoint,
        point,
        route: latestAvailableRoute(endpoint.routes, cursorMs)
          ?? [originPosition(scene.origin), endpoint.position],
      })
    }
  }

  activeEndpoints.sort((left, right) =>
    right.point.activeFlowCount - left.point.activeFlowCount
    || right.point.bytes - left.point.bytes
    || left.endpoint.ip.localeCompare(right.endpoint.ip),
  )

  const arcs: MapArc[] = []
  for (const { endpoint, point, route } of activeEndpoints) {
    for (let index = 1; index < route.length && arcs.length < maximumArcSegments; index += 1) {
      arcs.push({
        id: `${endpoint.id}:${index}`,
        sourcePosition: route[index - 1],
        targetPosition: route[index],
        activeFlowCount: point.activeFlowCount,
        bytes: point.bytes,
        tilt: deterministicTilt(endpoint.ip),
      })
    }
    if (arcs.length >= maximumArcSegments) break
  }

  return { points, arcs, seenFlowCount, activeFlowCount, byteCount }
}

function mapFlow(flow: Flow, fallbackStartMs: number): MapFlowInterval | null {
  const startMs = parseEpoch(flow.start || flow.created, fallbackStartMs)
  if (!Number.isFinite(startMs)) return null
  const endMs = Math.max(startMs, parseEpoch(flow.last_seen || flow.updated, startMs))
  return {
    id: flow.id,
    startMs,
    endMs,
    bytes: Math.max(0, flow.bytes_in || 0) + Math.max(0, flow.bytes_out || 0),
    packets: Math.max(0, flow.packets_in || 0) + Math.max(0, flow.packets_out || 0),
  }
}

function indexRoutes(
  routes: Route[],
  origin: GatewayOrigin,
  destinationsByIP: Map<string, Destination>,
) {
  const result = new Map<string, MapRoutePath[]>()
  for (const route of routes) {
    const destination = destinationsByIP.get(route.destination_ip)
    if (!destination) continue
    const positions = routePositions(route, origin, destination)
    if (positions.length < 2) continue
    const key = socketKey(route.destination_ip, route.destination_port, route.protocol)
    const paths = result.get(key)
    const path = {
      id: route.id,
      completedAtMs: parseEpoch(route.completed_at, Number.MAX_SAFE_INTEGER),
      positions,
    }
    if (paths) paths.push(path)
    else result.set(key, [path])
  }
  for (const paths of result.values()) {
    paths.sort((left, right) => left.completedAtMs - right.completedAtMs || left.id.localeCompare(right.id))
  }
  return result
}

function routePositions(route: Route, origin: GatewayOrigin, destination: Destination): MapPosition[] {
  const positions: MapPosition[] = [originPosition(origin)]
  for (const hop of route.hops ?? []) {
    const { lat, lon } = hop
    if (hop.missing || typeof lat !== 'number' || typeof lon !== 'number' || !validPosition(lon, lat)) continue
    appendUniquePosition(positions, [lon, lat])
  }
  appendUniquePosition(positions, [destination.lon, destination.lat])
  return positions
}

function latestAvailableRoute(routes: MapRoutePath[], cursorMs: number) {
  for (let index = routes.length - 1; index >= 0; index -= 1) {
    const route = routes[index]
    if (route.completedAtMs <= cursorMs) return route.positions
  }
  return null
}

function originPosition(origin: GatewayOrigin): MapPosition {
  return [origin.longitude, origin.latitude]
}

function appendUniquePosition(positions: MapPosition[], position: MapPosition) {
  const previous = positions[positions.length - 1]
  if (!previous || previous[0] !== position[0] || previous[1] !== position[1]) positions.push(position)
}

function hasCoordinates(destination: Destination) {
  return validPosition(destination.lon, destination.lat) && !(destination.lon === 0 && destination.lat === 0)
}

function validPosition(longitude: number | undefined, latitude: number | undefined): longitude is number {
  return Number.isFinite(longitude) && Number.isFinite(latitude)
    && longitude! >= -180 && longitude! <= 180
    && latitude! >= -90 && latitude! <= 90
}

function endpointLabel(destination: Destination) {
  return destination.reverse_dns
    || destination.provider_label
    || destination.organization
    || destination.city
    || destination.ip
}

function socketKey(ip: string, port: number, protocol: string) {
  return `${ip}:${port}:${protocol.toLowerCase()}`
}

function deterministicTilt(value: string) {
  let hash = 0
  for (let index = 0; index < value.length; index += 1) hash = ((hash << 5) - hash + value.charCodeAt(index)) | 0
  return (Math.abs(hash) % 21) - 10
}
