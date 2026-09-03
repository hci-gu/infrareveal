import type { PipelineDirection, PipelineEventKind, PipelineStage } from '../types'

export const PROXY_COMPOSITION_WIDTH = 1600
export const PROXY_COMPOSITION_HEIGHT = 900

export type GraphNodeId =
  | 'client' | 'wlan0' | 'dnsmasq' | 'conntrack' | 'header_capture' | 'flow_gate'
  | 'dns_gate'
  | 'forward' | 'nat' | 'remote' | 'drop' | 'correlator' | 'enricher' | 'route_worker'
  | 'pocketbase'

export type GraphNode = {
  id: GraphNodeId
  label: string
  labelLines?: readonly string[]
  x: number
  y: number
  plane: 'data' | 'observation'
}

export const GRAPH_NODES: readonly GraphNode[] = [
  { id: 'client', label: 'Client', x: 100, y: 350, plane: 'data' },
  { id: 'wlan0', label: 'wlan0', x: 300, y: 350, plane: 'data' },
  { id: 'conntrack', label: 'conntrack', x: 510, y: 350, plane: 'data' },
  { id: 'flow_gate', label: 'Flow gate', x: 710, y: 350, plane: 'data' },
  { id: 'forward', label: 'FORWARD', x: 910, y: 350, plane: 'data' },
  { id: 'nat', label: 'NAT', x: 1110, y: 350, plane: 'data' },
  { id: 'remote', label: 'Remote', x: 1480, y: 350, plane: 'data' },
  { id: 'drop', label: 'Drop', x: 710, y: 555, plane: 'data' },
  { id: 'dns_gate', label: 'DNS gate', x: 420, y: 130, plane: 'data' },
  { id: 'dnsmasq', label: 'dnsmasq', x: 620, y: 130, plane: 'observation' },
  {
    id: 'header_capture',
    label: 'Traffic activity capture',
    labelLines: ['Traffic activity', 'capture'],
    x: 510,
    y: 570,
    plane: 'observation',
  },
  { id: 'correlator', label: 'DNS attribution', x: 790, y: 115, plane: 'observation' },
  { id: 'enricher', label: 'GeoIP + reverse DNS', x: 1000, y: 115, plane: 'observation' },
  { id: 'route_worker', label: 'Traceroute', x: 1210, y: 115, plane: 'observation' },
  { id: 'pocketbase', label: 'PocketBase', x: 1000, y: 245, plane: 'observation' },
] as const

export type PathDefinition = {
  id: string
  nodes: readonly GraphNodeId[]
  plane: 'data' | 'observation' | 'mixed'
}

const paths = {
  flowOut: path('flow-out', ['client', 'wlan0', 'conntrack', 'flow_gate', 'forward', 'nat', 'remote'], 'data'),
  burstOut: path('burst-out', ['client', 'wlan0', 'header_capture', 'forward', 'nat', 'remote'], 'mixed'),
  burstIn: path('burst-in', ['remote', 'nat', 'forward', 'header_capture', 'wlan0', 'client'], 'mixed'),
  dnsOut: path('dns-out', ['client', 'wlan0', 'dnsmasq', 'pocketbase'], 'mixed'),
  dnsIn: path('dns-in', ['dnsmasq', 'wlan0', 'client'], 'mixed'),
  gateWait: path('gate-wait', ['conntrack', 'flow_gate'], 'data'),
  gateAccept: path('gate-accept', ['flow_gate', 'forward', 'nat', 'remote'], 'data'),
  gateWaitIn: path('gate-wait-in', ['remote', 'nat', 'forward', 'flow_gate'], 'data'),
  gateAcceptIn: path('gate-accept-in', ['flow_gate', 'conntrack', 'wlan0', 'client'], 'data'),
  gateDrop: path('gate-drop', ['flow_gate', 'drop'], 'data'),
  dnsGateWait: path('dns-gate-wait', ['client', 'wlan0', 'dns_gate'], 'data'),
  dnsGateAccept: path('dns-gate-accept', ['dns_gate', 'dnsmasq'], 'mixed'),
  dnsGateDrop: path('dns-gate-drop', ['dns_gate', 'drop'], 'data'),
  attribution: path('attribution', ['correlator', 'pocketbase'], 'observation'),
  destination: path('destination', ['enricher', 'pocketbase'], 'observation'),
  route: path('route', ['route_worker', 'pocketbase'], 'observation'),
} as const

export const GRAPH_PATHS: readonly PathDefinition[] = Object.values(paths)

export function pathForEvent(event: {
  kind: PipelineEventKind
  stage: PipelineStage
  direction?: PipelineDirection
  summary: { verdict?: string; remotePort?: number }
}): PathDefinition {
  if (event.kind === 'health') throw new Error('Activity quality is timeline metadata and has no pipeline path.')
  if (event.kind === 'dns') return event.direction === 'remote_to_client' ? paths.dnsIn : paths.dnsOut
  if (event.kind === 'burst') return event.direction === 'remote_to_client' ? paths.burstIn : paths.burstOut
  if (event.kind === 'gate') {
    if (event.summary.remotePort === 53) {
      if (event.summary.verdict === 'rejected') return paths.dnsGateDrop
      if (event.summary.verdict) return paths.dnsGateAccept
      return paths.dnsGateWait
    }
    if (event.summary.verdict === 'rejected') return paths.gateDrop
    if (event.summary.verdict) return event.direction === 'remote_to_client' ? paths.gateAcceptIn : paths.gateAccept
    return event.direction === 'remote_to_client' ? paths.gateWaitIn : paths.gateWait
  }
  if (event.kind === 'attribution') return paths.attribution
  if (event.kind === 'destination') return paths.destination
  if (event.kind === 'route') return paths.route
  return paths.flowOut
}

export function nodeById(id: GraphNodeId) {
  const node = GRAPH_NODES.find((candidate) => candidate.id === id)
  if (!node) throw new Error(`Unknown graph node: ${id}`)
  return node
}

function path(id: string, nodes: readonly GraphNodeId[], plane: PathDefinition['plane']): PathDefinition {
  return { id, nodes, plane }
}
