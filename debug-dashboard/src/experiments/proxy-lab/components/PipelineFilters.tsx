import type { PipelineEvent, PipelineEventKind } from '../types'
import type { ProxyLabFilters } from '../state/proxyLabStore'

export function PipelineFilters({ events, filters, onChange }: {
  events: readonly PipelineEvent[]
  filters: ProxyLabFilters
  onChange: (filters: Partial<ProxyLabFilters>) => void
}) {
  const clients = unique(events.flatMap((event) => event.summary.clientIp ? [event.summary.clientIp] : []))
  const protocols = unique(events.flatMap((event) => event.summary.protocol ? [event.summary.protocol.toLowerCase()] : []))
  const kinds = unique(events.map((event) => event.kind))
  return (
    <div className="space-y-3 border border-slate-800 bg-slate-900/70 p-3">
      <FilterRow label="Clients" values={clients} selected={filters.clientIps} onChange={(clientIps) => onChange({ clientIps })} />
      <FilterRow label="Protocols" values={protocols} selected={filters.protocols} onChange={(values) => onChange({ protocols: values })} />
      <FilterRow label="Signals" values={kinds} selected={filters.kinds} onChange={(values) => onChange({ kinds: values as PipelineEventKind[] })} />
    </div>
  )
}

function FilterRow({ label, values, selected, onChange }: {
  label: string
  values: string[]
  selected: string[]
  onChange: (values: string[]) => void
}) {
  return (
    <div>
      <div className="mb-1 text-[10px] font-bold uppercase tracking-[0.16em] text-slate-500">{label}</div>
      <div className="flex flex-wrap gap-1.5">
        {values.length === 0 ? <span className="text-xs text-slate-600">No values yet</span> : values.map((value) => {
          const active = selected.includes(value)
          return (
            <button
              aria-pressed={active}
              className={`border px-2 py-1 font-mono text-[11px] ${active ? 'border-cyan-600 bg-cyan-950 text-cyan-200' : 'border-slate-700 text-slate-400'}`}
              key={value}
              onClick={() => onChange(active ? selected.filter((item) => item !== value) : [...selected, value])}
              type="button"
            >{value}</button>
          )
        })}
      </div>
    </div>
  )
}

function unique<T extends string>(values: T[]) {
  return Array.from(new Set(values)).sort()
}
