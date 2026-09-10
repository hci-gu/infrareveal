import { useMemo, useRef, type CSSProperties } from 'react'
import { GRAPH_NODES, GRAPH_PATHS, type GraphNodeId, type PathDefinition } from '../model/graphLayout'
import { projectProxyScene } from '../model/projectProxyScene'
import { TemporalEventIndex } from '../model/temporalEventIndex'
import type { GraphTransform } from '../model/graphViewState'
import type { PipelineEvent } from '../types'
import { useElementSize } from '../../../shared/ui/useElementSize'

const positions: Record<GraphNodeId, [number, number]> = {
  client: [90, 305], wlan0: [280, 305], conntrack: [470, 305], flow_gate: [660, 305], forward: [850, 305], nat: [1040, 305], remote: [1230, 305],
  dns_gate: [280, 108], dnsmasq: [480, 108], correlator: [700, 108], enricher: [930, 108], route_worker: [1170, 108],
  drop: [660, 470], header_capture: [370, 555], pocketbase: [990, 555],
}
const labels: Partial<Record<GraphNodeId, string[]>> = { header_capture: ['Activity capture'], enricher: ['Destination'], correlator: ['DNS attribution'], route_worker: ['Route probe'] }
const subtitles: Record<GraphNodeId, string> = { client: 'Observed client', wlan0: 'Gateway ingress', conntrack: 'Connection state', flow_gate: 'Flow admission', forward: 'Forwarding', nat: 'Address translation', remote: 'Endpoint', drop: 'Rejected traffic', dns_gate: 'Local DNS control', dnsmasq: 'DNS observation', header_capture: 'Passive header tap', correlator: 'Derived hostname', enricher: 'ASN / provider', route_worker: 'Gateway approximation', pocketbase: 'Durable evidence' }
const observationEdges: [GraphNodeId, GraphNodeId][] = [['wlan0', 'header_capture'], ['header_capture', 'pocketbase'], ['dnsmasq', 'correlator'], ['correlator', 'pocketbase'], ['enricher', 'pocketbase'], ['route_worker', 'pocketbase']]
const edges = new Map<string, { from: GraphNodeId; to: GraphNodeId; observation: boolean }>()
for (const path of GRAPH_PATHS) for (let i = 1; i < path.nodes.length; i++) {
  const from = path.nodes[i - 1], to = path.nodes[i]
  edges.set(`${from}:${to}`, { from, to, observation: path.plane === 'observation' || to === 'pocketbase' })
}
for (const [from, to] of observationEdges) edges.set(`${from}:${to}`, { from, to, observation: true })

export function GraphViewport({ events, cursorMs, selectedEventId, path, selectedNode, branches, transform, onTransform, onSelect, reduceMotion }: {
  events: PipelineEvent[]; cursorMs: number; selectedEventId: string | null; path: PathDefinition | null; selectedNode: GraphNodeId | null; branches: boolean; transform: GraphTransform; onTransform: (value: GraphTransform) => void; onSelect: (id: GraphNodeId) => void; reduceMotion: boolean
}) {
  const { ref: containerRef, width, height } = useElementSize<HTMLDivElement>()
  const drag = useRef<{ x: number; y: number; transform: GraphTransform } | null>(null)
  const index = useMemo(() => (() => { const index = new TemporalEventIndex(); index.synchronize(events); return index })(), [events])
  const scene = useMemo(() => projectProxyScene(index.query(cursorMs - 2_000, cursorMs + 1), cursorMs, { selectedId: selectedEventId, maxVisibleTokens: 100 }), [cursorMs, index, selectedEventId])
  const fit = Math.max(0.65, Math.min((width || 1000) / 1340, (height || 640) / 650))
  const zoom = Math.min(2.5, Math.max(0.65, fit * (Number.isFinite(transform.zoom) ? transform.zoom : 1)))
  const offset = { x: ((width || 1000) - 1340 * fit) / 2 + (Number.isFinite(transform.x) ? transform.x : 0), y: ((height || 640) - 650 * fit) / 2 + (Number.isFinite(transform.y) ? transform.y : 0) }
  const visibleNode = (id: GraphNodeId) => branches || GRAPH_NODES.find(n => n.id === id)?.plane === 'data' || id === 'dnsmasq'
  return <div ref={containerRef} className="lab-graph-viewport" tabIndex={0} aria-label="Gateway graph. Drag background to pan, use zoom controls, or arrow keys to pan." onKeyDown={event => {
    if (event.target !== event.currentTarget) return
    const delta = 40
    if (['ArrowLeft','ArrowRight','ArrowUp','ArrowDown'].includes(event.key)) { event.preventDefault(); onTransform({ ...transform, x: transform.x + (event.key === 'ArrowLeft' ? delta : event.key === 'ArrowRight' ? -delta : 0), y: transform.y + (event.key === 'ArrowUp' ? delta : event.key === 'ArrowDown' ? -delta : 0) }) }
  }} onPointerDown={event => {
    if (event.button !== 0 || (event.target as Element).closest('[data-node]')) return
    drag.current = { x: event.clientX, y: event.clientY, transform }; event.currentTarget.setPointerCapture(event.pointerId)
  }} onPointerMove={event => { if (drag.current) onTransform({ ...drag.current.transform, x: drag.current.transform.x + event.clientX - drag.current.x, y: drag.current.transform.y + event.clientY - drag.current.y }) }} onPointerUp={() => { drag.current = null }} onPointerCancel={() => { drag.current = null }}>
    <div className="lab-graph-plane" style={{ width: 1340, height: 650, transform: `translate(${offset.x}px,${offset.y}px) scale(${zoom})` } as CSSProperties}>
      <svg width="1340" height="650" aria-hidden="true"><defs><marker id="lab-arrow" markerWidth="6" markerHeight="6" refX="5" refY="3" orient="auto"><path d="M0 0L6 3L0 6" fill="currentColor" /></marker></defs>
        {[...edges.entries()].map(([key, edge]) => {
          if (!visibleNode(edge.from) || !visibleNode(edge.to)) return null
          const [x1,y1] = positions[edge.from], [x2,y2] = positions[edge.to]
          const selected = path?.nodes.some((id, i) => id === edge.from && path.nodes[i + 1] === edge.to)
          const dx=x2-x1,dy=y2-y1, length=Math.hypot(dx,dy), padding = Math.abs(dx) > Math.abs(dy) ? 76 : 32
          const endX=x2-dx/length*padding,endY=y2-dy/length*padding
          return <line key={key} x1={x1} y1={y1} x2={endX} y2={endY} className={`lab-edge ${edge.observation ? 'observation' : ''} ${selected ? 'selected' : ''}`} markerEnd="url(#lab-arrow)" />
        })}
        {!reduceMotion && scene.tokens.slice(0, 100).map(token => {
          if (!token.path.nodes.every(visibleNode)) return null
          const progress=Math.max(0,Math.min(1,(cursorMs-token.startMs)/(token.endMs-token.startMs))), scaled=progress*(token.path.nodes.length-1), i=Math.min(token.path.nodes.length-2,Math.floor(scaled)), t=scaled-i
          const a=positions[token.path.nodes[i]],b=positions[token.path.nodes[i+1]]
          return <circle key={token.id} cx={a[0]+(b[0]-a[0])*t} cy={a[1]+(b[1]-a[1])*t+token.laneOffset} r={4.5*token.scale} fill={token.color} />
        })}
      </svg>
      <span className="lab-plane-label" style={{ left: 22, top: 220 }}>FORWARDING PATH</span>
      {branches ? <span className="lab-plane-label observation" style={{ left: 785, top: 605 }}>OBSERVATION &amp; DURABLE EVIDENCE</span> : null}
      {GRAPH_NODES.filter(n => visibleNode(n.id)).map(node => <button type="button" data-node={node.id} key={node.id} aria-pressed={selectedNode === node.id} aria-label={`Inspect ${node.label} node`} className={`lab-node ${node.plane} ${path?.nodes.includes(node.id) ? 'on-path' : ''} ${node.id === 'flow_gate' || node.id === 'dns_gate' ? 'gate' : ''} ${node.id === 'drop' ? 'drop' : ''}`} style={{ left: positions[node.id][0], top: positions[node.id][1] }} onClick={() => onSelect(node.id)}><strong>{labels[node.id]?.[0] || node.label}</strong><span>{subtitles[node.id]}</span></button>)}
    </div>
    <span className="lab-canvas-hint">Drag to pan · Select a node to inspect · Arrows explain direction, not measured latency</span>
  </div>
}
