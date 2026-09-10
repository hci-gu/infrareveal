import { flowTrackAt, indexFlowTracks, isTrafficConnection, parseEpoch } from '@infrareveal/session-state'
import type { Flow, FlowTrackIdentity, GatewayData } from '@infrareveal/session-state'
import type { MapEndpoint, MapTimelineScene } from './mapModel'
import type { TrafficProfile } from './mapTraffic'

export type TrackColor = [number, number, number]
const PALETTE: TrackColor[] = [[104, 222, 193], [175, 148, 246], [247, 181, 100], [106, 184, 250], [239, 135, 160], [199, 216, 112], [104, 213, 230], [226, 164, 235], [239, 144, 101], [131, 201, 139], [162, 181, 226], [215, 198, 171]]

export type MapConnection = FlowTrackIdentity & {
  flow: Flow
  startMs: number
  endMs: number
  bytes: number
  active: boolean
  mapped: boolean
  location: string
  provider: string
}
export type MapTrack = Pick<FlowTrackIdentity, 'id' | 'label' | 'client' | 'site' | 'episode'> & {
  color: TrackColor
  connections: MapConnection[]
  bytes: number
  activeCount: number
  mappedCount: number
}
export type MapTrackCatalog = ReturnType<typeof buildMapTrackCatalog>

/** Retain assigned colors across live revisions, independent of list sorting or selection. */
export class TrackColors {
  private colors = new Map<string, TrackColor>()
  get(id: string): TrackColor {
    let color = this.colors.get(id)
    if (!color) {
      const index = this.colors.size
      color = index < PALETTE.length ? PALETTE[index] : hueColor((index * 137.508) % 360)
      this.colors.set(id, color)
    }
    return color
  }
}

export function buildMapTrackCatalog(data: GatewayData, colors = new TrackColors()) {
  const flows = data.flows.filter(isTrafficConnection).sort((a, b) => parseEpoch(a.start, 0) - parseEpoch(b.start, 0) || a.id.localeCompare(b.id))
  const index = indexFlowTracks(data)
  for (const flow of flows) {
    colors.get(`${flow.client_ip}:independent`)
    for (const record of index.evidence.get(flow.id)?.associations ?? []) colors.get(`${flow.client_ip}:activity:${record.episode}`)
  }
  return { flows, index, colors, destinations: new Map(data.destinations.map(destination => [destination.ip, destination])), data }
}

export function projectMapTracks(catalog: MapTrackCatalog, scene: MapTimelineScene, cursorMs: number) {
  const groups = new Map<string, MapTrack>()
  const byFlow = new Map<string, MapConnection>()
  const mappedIPs = new Set(scene.endpoints.filter(endpoint => endpoint.availableFromMs <= cursorMs).map(endpoint => endpoint.ip))
  for (const flow of catalog.flows) {
    const startMs = parseEpoch(flow.start || flow.created, Infinity)
    if (startMs > cursorMs) continue
    const endMs = Math.max(startMs, parseEpoch(flow.last_seen || flow.updated, startMs))
    const identity = flowTrackAt(catalog.index, flow, cursorMs)
    const destination = catalog.destinations.get(flow.destination_ip)
    const connection: MapConnection = {
      ...identity, flow, startMs, endMs, bytes: Math.max(0, flow.bytes_in || 0) + Math.max(0, flow.bytes_out || 0), active: cursorMs <= endMs + 5000,
      mapped: mappedIPs.has(flow.destination_ip),
      location: destination ? [destination.city, destination.country].filter(Boolean).join(', ') : '',
      provider: destination?.provider_label || destination?.organization || '',
    }
    const group = groups.get(identity.id) ?? { ...identity, color: catalog.colors.get(identity.id), connections: [], bytes: 0, activeCount: 0, mappedCount: 0 }
    group.connections.push(connection)
    group.bytes += connection.bytes
    group.activeCount += Number(connection.active)
    group.mappedCount += Number(connection.mapped)
    groups.set(group.id, group)
    byFlow.set(flow.id, connection)
  }
  const tracks = [...groups.values()].sort((a, b) => b.bytes - a.bytes || a.id.localeCompare(b.id))
  return { tracks, byFlow }
}

/** Split shared IPs by track before bundling or measuring volume; each flow contributes exactly once. */
export function sceneForTracks(scene: MapTimelineScene, byFlow: Map<string, MapConnection>): MapTimelineScene {
  const endpoints: MapEndpoint[] = []
  for (const endpoint of scene.endpoints) {
    const groups = new Map<string, MapEndpoint>()
    for (const flow of endpoint.flows) {
      const connection = byFlow.get(flow.id)
      if (!connection) continue
      const routeKey = JSON.stringify([connection.id, flow.routeIds ?? []])
      let group = groups.get(routeKey)
      if (!group) {
        group = { ...endpoint, id: JSON.stringify([endpoint.id, routeKey]), trackId: connection.id, flows: [] }
        groups.set(routeKey, group)
      }
      group.flows.push(flow)
    }
    for (const group of groups.values()) {
      const routeIds = new Set(group.flows.flatMap(flow => flow.routeIds ?? []))
      group.routes = endpoint.routes.filter(route => routeIds.has(route.id))
      endpoints.push(group)
    }
  }
  return { ...scene, endpoints }
}

export function trackTraffic(track: MapTrack, scene: MapTimelineScene, profiles: Map<string, TrafficProfile>) {
  const parts = scene.endpoints.filter(endpoint => endpoint.trackId === track.id).map(endpoint => profiles.get(endpoint.id)).filter((profile): profile is TrafficProfile => Boolean(profile))
  return { rate: parts.reduce((sum, profile) => sum + profile.rates[0], 0), estimated: parts.some(profile => profile.source === 'estimated'), partial: track.mappedCount < track.connections.length || parts.some(profile => profile.source === 'partial'), available: parts.some(profile => profile.source !== 'unavailable') }
}

export function trackOpacity(trackId: string | undefined, selectedId: string | null) {
  return !selectedId || trackId === selectedId ? 1 : 0.09
}
export function colorCSS(color: TrackColor) { return `rgb(${color.join(' ')})` }
function hueColor(hue: number): TrackColor {
  const f = (n: number) => {
    const k = (n + hue / 30) % 12
    return Math.round(255 * (0.68 - 0.55 * 0.32 * Math.max(-1, Math.min(k - 3, 9 - k, 1))))
  }
  return [f(0), f(8), f(4)]
}
