import type { PipelineDirection, PipelineEventKind, PipelineStage } from '../types'

export type GraphNodeId =
  | 'client' | 'wlan0' | 'dnsmasq' | 'conntrack' | 'header_capture' | 'flow_gate'
  | 'dns_gate'
  | 'forward' | 'nat' | 'remote' | 'drop' | 'correlator' | 'enricher' | 'route_worker'
  | 'pocketbase'

export type GraphNode = {
  id: GraphNodeId
  label: string
  x: number
  y: number
  plane: 'data' | 'observation'
}

export const GRAPH_NODES: readonly GraphNode[] = [
  { id: 'client', label: 'Client', x: 90, y: 305, plane: 'data' },
  { id: 'wlan0', label: 'wlan0', x: 280, y: 305, plane: 'data' },
  { id: 'conntrack', label: 'conntrack', x: 470, y: 305, plane: 'data' },
  { id: 'flow_gate', label: 'Flow gate', x: 660, y: 305, plane: 'data' },
  { id: 'forward', label: 'FORWARD', x: 850, y: 305, plane: 'data' },
  { id: 'nat', label: 'NAT', x: 1040, y: 305, plane: 'data' },
  { id: 'remote', label: 'Remote', x: 1230, y: 305, plane: 'data' },
  { id: 'drop', label: 'Drop', x: 660, y: 470, plane: 'data' },
  { id: 'dns_gate', label: 'DNS gate', x: 280, y: 108, plane: 'data' },
  { id: 'dnsmasq', label: 'dnsmasq', x: 480, y: 108, plane: 'observation' },
  { id: 'header_capture', label: 'Traffic activity capture', x: 370, y: 555, plane: 'observation' },
  { id: 'correlator', label: 'DNS attribution', x: 700, y: 108, plane: 'observation' },
  { id: 'enricher', label: 'GeoIP + reverse DNS', x: 930, y: 108, plane: 'observation' },
  { id: 'route_worker', label: 'Traceroute', x: 1170, y: 108, plane: 'observation' },
  { id: 'pocketbase', label: 'PocketBase', x: 990, y: 555, plane: 'observation' },
] as const

const nodesById = new Map(GRAPH_NODES.map(node => [node.id, node]))

export type PathDefinition = {
  id: string
  nodes: readonly GraphNodeId[]
  plane: 'data' | 'observation' | 'mixed'
}

const paths = {
  flowOut: path('flow-out', ['client', 'wlan0', 'conntrack', 'flow_gate', 'forward', 'nat', 'remote'], 'data'),
  flowIn: path('flow-in', ['remote', 'nat', 'forward', 'flow_gate', 'conntrack', 'wlan0', 'client'], 'data'),
  burstOut: path('burst-out', ['client', 'wlan0', 'conntrack', 'flow_gate', 'forward', 'nat', 'remote'], 'data'),
  burstIn: path('burst-in', ['remote', 'nat', 'forward', 'flow_gate', 'conntrack', 'wlan0', 'client'], 'data'),
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
  return event.direction === 'remote_to_client' ? paths.flowIn : paths.flowOut
}

export function nodeById(id: GraphNodeId) {
  const node = nodesById.get(id)
  if (!node) throw new Error(`Unknown graph node: ${id}`)
  return node
}

function path(id: string, nodes: readonly GraphNodeId[], plane: PathDefinition['plane']): PathDefinition {
  return { id, nodes, plane }
}
