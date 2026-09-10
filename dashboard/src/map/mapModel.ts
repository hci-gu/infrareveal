import type { Destination, Flow, GatewayData, Route } from '@infrareveal/session-state'
import { isTrafficConnection, parseEpoch, routeForFlowAt } from '@infrareveal/session-state'
import { hasMapCoordinates, mapRoutePath, routeProgress } from './mapRoutes'
import type { RouteNode } from './mapRoutes'

export type MapPosition = [longitude: number, latitude: number]

export type GatewayOrigin = {
  latitude: number
  longitude: number
  label: string
}

export type MapFlowInterval = {
  id: string
  routeIds?: string[]
  startMs: number
  endMs: number
  bytes: number
  packets: number
  bytesIn?: number
  bytesOut?: number
  packetsIn?: number
  packetsOut?: number
}

export type MapRoutePath = {
  evidence?: Route
  id: string
  completedAtMs: number
  positions: MapPosition[]
  nodes: RouteNode[]
  gaps: boolean[]
  complete: boolean
}

export type MapHopPoint = RouteNode & { id: string; trackId?: string; routeId: string }

export type MapEndpoint = {
  id: string
  trackId?: string
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
  trackId?: string
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
  trackId?: string
  endpointId: string
  sourcePosition: MapPosition
  targetPosition: MapPosition
  activeFlowCount: number
  bytes: number
  tilt: number
  routeId?: string
  gap?: boolean
  progressStart?: number
  progressEnd?: number
}

export type MapFrame = {
  points: MapPoint[]
  arcs: MapArc[]
  hops: MapHopPoint[]
  seenFlowCount: number
  activeFlowCount: number
  byteCount: number
}

const ACTIVE_TRAIL_MS = 5_000
const MAX_ARC_SEGMENTS = 4_000

/** Builds a compact, serializable model once per overview revision. */
export function buildMapTimelineScene(data: GatewayData, origin: GatewayOrigin, canonicalStartMs?: number): MapTimelineScene {
  const session = data.selectedSession
  const clientFlows = data.flows.filter(isTrafficConnection)
  const sessionStartMs = Number.isFinite(canonicalStartMs)
    ? canonicalStartMs!
    : parseEpoch(session?.started_at || session?.created, 0)
  const destinationsByIP = new Map(
    data.destinations
      .map((destination) => [destination.ip, destination]),
  )
  for (const flow of clientFlows) if (!destinationsByIP.has(flow.destination_ip)) {
    destinationsByIP.set(flow.destination_ip, {id: flow.destination_ip, ip: flow.destination_ip, reverse_dns:'', asn:0, organization:'', provider_label:'', city:'', country:'', lat:0, lon:0, last_seen:flow.last_seen})
  }
  const routesBySocket = indexRoutes(data.routes.filter(route => !session || route.session === session.id), origin, destinationsByIP)
  const flowsByDestination = new Map<string, MapFlowInterval[]>()
  const routesByDestination = new Map<string, Map<string, MapRoutePath>>()

  for (const flow of clientFlows) {
    const interval = mapFlow(flow, sessionStartMs)
    if (!interval) continue
    const paths = routesBySocket.get(socketKey(flow.destination_ip, flow.destination_port, flow.protocol)) ?? []
    const location = destinationsByIP.get(flow.destination_ip)!
    if (!hasMapCoordinates(location.lat, location.lon) && !paths.some(path => path.positions.length > 1)) continue
    const flows = flowsByDestination.get(flow.destination_ip)
    if (flows) flows.push(interval)
    else flowsByDestination.set(flow.destination_ip, [interval])

    interval.routeIds = paths.map(path => path.id)
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
      availableFromMs: Math.max(firstSeenMs, Math.min(destinationCreatedMs, ...routes.map(route => route.completedAtMs))),
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
    totalFlowCount: clientFlows.length,
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
  const connectedEndpoints: Array<{ endpoint: MapEndpoint; point: MapPoint; route: MapRoutePath | null }> = []
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

    const route = latestAvailableRoute(endpoint.routes, cursorMs)
    const location = route?.evidence?.destination_location
    const point: MapPoint = {
      id: endpoint.id,
      trackId: endpoint.trackId,
      ip: endpoint.ip,
      label: endpoint.label,
      provider: endpoint.provider,
      location: [endpoint.city, endpoint.country].filter(Boolean).join(', '),
      position: location ? [location.lon, location.lat] : endpoint.position,
      flowCount: endpointSeenFlows,
      activeFlowCount: endpointActiveFlows,
      bytes: endpointBytes,
    }
    if (hasMapCoordinates(point.position[1], point.position[0])) points.push(point)
    seenFlowCount += endpointSeenFlows
    activeFlowCount += endpointActiveFlows
    byteCount += endpointBytes

    // Keep the connection visible while its volume can swell or fall back to zero.
    connectedEndpoints.push({
      endpoint,
      point,
      route,
    })
  }

  connectedEndpoints.sort((left, right) =>
    right.point.activeFlowCount - left.point.activeFlowCount
    || right.point.bytes - left.point.bytes
    || left.endpoint.ip.localeCompare(right.endpoint.ip),
  )

  const arcs: MapArc[] = []
  const hops = new Map<string, MapHopPoint>()
  for (const { endpoint, point, route } of connectedEndpoints) {
    const positions = route?.positions ?? (hasMapCoordinates(endpoint.position[1], endpoint.position[0]) ? [originPosition(scene.origin), endpoint.position] : [])
    // Keep complete paths when the display budget is exhausted.
    if (arcs.length + positions.length - 1 > maximumArcSegments) continue
    const progress = routeProgress(positions)
    for (let index = 1; index < positions.length && arcs.length < maximumArcSegments; index += 1) {
      arcs.push({
        id: `${endpoint.id}:${index}`,
        trackId: endpoint.trackId,
        endpointId: endpoint.id,
        sourcePosition: positions[index - 1],
        targetPosition: positions[index],
        activeFlowCount: point.activeFlowCount,
        bytes: point.bytes,
        tilt: deterministicTilt(endpoint.ip),
        routeId: route?.id,
        gap: route?.gaps[index - 1] ?? true,
        progressStart: progress[index - 1],
        progressEnd: progress[index],
      })
      const hop = route?.nodes[index]
      if (hop?.kind === 'hop') {
        const id = `${endpoint.trackId ?? ''}/${route!.id}/${hop.ttl}/${hop.address}`
        hops.set(id, { ...hop, id, trackId: endpoint.trackId, routeId: route!.id })
      }
    }
    if (arcs.length >= maximumArcSegments) break
  }

  return { points, arcs, hops: [...hops.values()], seenFlowCount, activeFlowCount, byteCount }
}

function mapFlow(flow: Flow, fallbackStartMs: number): MapFlowInterval | null {
  const startMs = parseEpoch(flow.start || flow.created, fallbackStartMs)
  if (!Number.isFinite(startMs)) return null
  const endMs = Math.max(startMs, parseEpoch(flow.last_seen || flow.updated, startMs))
  return {
    id: flow.id,
    startMs,
    endMs,
    bytesIn: Math.max(0, flow.bytes_in || 0), bytesOut: Math.max(0, flow.bytes_out || 0), packetsIn: Math.max(0, flow.packets_in || 0), packetsOut: Math.max(0, flow.packets_out || 0),
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
    const path = mapRoutePath(route, origin, destination)
    const key = socketKey(route.destination_ip, route.destination_port, route.protocol)
    const paths = result.get(key)
    if (paths) paths.push(path)
    else result.set(key, [path])
  }
  for (const paths of result.values()) {
    paths.sort((left, right) => left.completedAtMs - right.completedAtMs || left.id.localeCompare(right.id))
  }
  return result
}

function latestAvailableRoute(routes: MapRoutePath[], cursorMs: number) {
  const evidence = routes.flatMap(path => path.evidence ? [path.evidence] : [])
  if (evidence.length) {
    // A destination can have several socket keys. Select within each key first
    // so an expired binding never resurrects its own older revision.
    const selected = evidence.map(route => routeForFlowAt(route, evidence, cursorMs)).filter((r): r is Route => r !== null)
    selected.sort((a,b) => (a.available_at || a.completed_at).localeCompare(b.available_at || b.completed_at))
    const latest = selected[selected.length - 1]
    return latest ? routes.find(path => path.id === latest.id) ?? null : null
  }
  return [...routes].reverse().find(route => route.completedAtMs <= cursorMs) ?? null
}

function originPosition(origin: GatewayOrigin): MapPosition {
  return [origin.longitude, origin.latitude]
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
