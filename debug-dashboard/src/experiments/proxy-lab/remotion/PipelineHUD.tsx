import type { PipelineEvent, ProxyLabMode } from '../types'
import type { ProxyScene } from '../model/projectProxyScene'

export function PipelineHUD({ cursorMs, mode, scene, selected }: {
  cursorMs: number
  mode: ProxyLabMode
  scene: ProxyScene
  selected: PipelineEvent | null
}) {
  return (
    <>
      <div style={{ left: 34, position: 'absolute', top: 28, color: '#f8fafc', fontFamily: 'Inter, sans-serif' }}>
        <div style={{ fontSize: 14, fontWeight: 800, letterSpacing: 3, textTransform: 'uppercase' }}>Proxy pipeline · {mode}</div>
        <div style={{ color: '#94a3b8', fontFamily: 'ui-monospace, monospace', fontSize: 13, marginTop: 5 }}>
          {new Date(cursorMs).toISOString()} · {scene.totalActiveTokens} active
        </div>
      </div>
      <div style={{ color: '#64748b', fontFamily: 'ui-monospace, monospace', fontSize: 11, letterSpacing: 1.5, position: 'absolute', right: 34, textTransform: 'uppercase', top: 31 }}>
        Rendered from PocketBase history + optional live trace
      </div>
      {selected ? (
        <div style={{ background: 'rgba(2, 6, 23, .9)', border: '1px solid #334155', bottom: 26, color: '#e2e8f0', maxWidth: 470, padding: '15px 18px', position: 'absolute', right: 26 }}>
          <div style={{ color: selected.timing === 'derived' ? '#c4b5fd' : '#86efac', fontSize: 12, fontWeight: 800, letterSpacing: 2 }}>
            {selected.timing === 'derived' ? 'DERIVED TIMING' : 'OBSERVED'}
          </div>
          <div style={{ fontFamily: 'ui-monospace, monospace', fontSize: 14, marginTop: 6 }}>
            {selected.kind} · {selected.stage}
          </div>
          {selected.kind === 'route' ? <div style={{ color: '#94a3b8', fontSize: 12, marginTop: 5 }}>Gateway approximation; not the client packet path.</div> : null}
        </div>
      ) : null}
    </>
  )
}
