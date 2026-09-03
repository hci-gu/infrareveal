import { GRAPH_NODES, GRAPH_PATHS, nodeById } from '../model/graphLayout'
import type { ProxyScene } from '../model/projectProxyScene'
import type { ProxyLabMode } from '../types'
import { TrafficToken } from './TrafficToken'

export function PipelineGraph({ scene, mode }: { scene: ProxyScene; mode: ProxyLabMode }) {
  const edges = uniqueEdges()
  return (
    <svg aria-label="Gateway packet and observation pipeline" height="100%" role="img" viewBox="0 0 1600 900" width="100%">
      <defs>
        <pattern height="16" id="unknown-hatch" patternUnits="userSpaceOnUse" width="16">
          <path d="M-4 4L4-4M0 16L16 0M12 20L20 12" stroke="#fb923c" strokeOpacity="0.23" strokeWidth="3" />
        </pattern>
        <filter id="token-glow"><feGaussianBlur stdDeviation="4" /></filter>
      </defs>
      <rect fill="#020617" height="900" width="1600" />
      {scene.tokens.some((token) => token.stage === 'health') ? (
        <rect fill="url(#unknown-hatch)" height="900" width="1600" />
      ) : null}
      <text fill="#64748b" fontFamily="ui-monospace, monospace" fontSize="18" letterSpacing="4" x="80" y="60">DATA PLANE</text>
      <text fill="#64748b" fontFamily="ui-monospace, monospace" fontSize="18" letterSpacing="4" x="80" y="650">OBSERVATION / DERIVATION</text>
      {edges.map((edge) => (
        <line
          key={edge.id}
          stroke={edge.plane === 'data' ? '#334155' : '#475569'}
          strokeDasharray={edge.plane === 'data' ? undefined : '10 10'}
          strokeWidth={edge.plane === 'data' ? 4 : 2}
          x1={edge.from.x}
          x2={edge.to.x}
          y1={edge.from.y}
          y2={edge.to.y}
        />
      ))}
      {GRAPH_NODES.map((node) => {
        const gateDimmed = (node.id === 'flow_gate' && mode !== 'turn-based' && mode !== 'strict') || (node.id === 'dns_gate' && mode !== 'dns')
        return (
          <g key={node.id} opacity={gateDimmed ? 0.38 : 1}>
            <rect
              fill={node.plane === 'data' ? '#0f172a' : '#111827'}
              height="62"
              rx="6"
              stroke={node.id === 'flow_gate' ? '#f59e0b' : node.id === 'dns_gate' ? '#22d3ee' : node.plane === 'data' ? '#475569' : '#6d28d9'}
              strokeDasharray={node.plane === 'observation' ? '6 5' : undefined}
              strokeWidth="2"
              width="150"
              x={node.x - 75}
              y={node.y - 31}
            />
            <text fill="#e2e8f0" fontFamily="Inter, sans-serif" fontSize="17" fontWeight="650" textAnchor="middle" x={node.x} y={node.y + 6}>
              {node.label}
            </text>
          </g>
        )
      })}
      {scene.tokens.map((token) => <TrafficToken cursorMs={scene.cursorMs} key={token.id} token={token} />)}
    </svg>
  )
}

function uniqueEdges() {
  const result = new Map<string, { id: string; from: ReturnType<typeof nodeById>; to: ReturnType<typeof nodeById>; plane: 'data' | 'observation' }>()
  for (const path of GRAPH_PATHS) {
    for (let index = 0; index < path.nodes.length - 1; index += 1) {
      const from = nodeById(path.nodes[index])
      const to = nodeById(path.nodes[index + 1])
      const id = `${from.id}:${to.id}`
      const plane = from.plane === 'data' && to.plane === 'data' ? 'data' : 'observation'
      result.set(id, { id, from, to, plane })
    }
  }
  return Array.from(result.values())
}
