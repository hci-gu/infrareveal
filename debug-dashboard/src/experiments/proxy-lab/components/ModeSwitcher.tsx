import type { ProxyLabMode } from '../types'

const modes: Array<{ id: ProxyLabMode; label: string; detail: string }> = [
  { id: 'replay', label: 'Replay', detail: 'Durable session data' },
  { id: 'live-observe', label: 'Live observe', detail: 'Passive trace stream' },
  { id: 'turn-based', label: 'Turn based', detail: 'Hold new flows' },
  { id: 'strict', label: 'Strict', detail: 'One exact flow' },
  { id: 'dns', label: 'DNS gate', detail: 'Hold selected DNS' },
]

export function ModeSwitcher({ mode, onChange }: { mode: ProxyLabMode; onChange: (mode: ProxyLabMode) => void }) {
  return (
    <div aria-label="Proxy lab mode" className="grid grid-cols-2 gap-2 2xl:grid-cols-3" role="group">
      {modes.map((item) => (
        <button
          aria-pressed={mode === item.id}
          className={`border px-3 py-2 text-left ${mode === item.id ? 'border-cyan-500 bg-cyan-950 text-cyan-100' : 'border-slate-700 bg-slate-900 text-slate-300 hover:border-slate-500'}`}
          key={item.id}
          onClick={() => onChange(item.id)}
          type="button"
        >
          <span className="block text-sm font-semibold">{item.label}</span>
          <span className="block text-[11px] text-slate-500">{item.detail}</span>
        </button>
      ))}
    </div>
  )
}
