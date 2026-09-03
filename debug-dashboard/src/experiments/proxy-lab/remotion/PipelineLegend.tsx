const items = [
  ['#22d3ee', 'Outbound'],
  ['#4ade80', 'Inbound'],
  ['#a78bfa', 'Derived'],
  ['#facc15', 'Held'],
  ['#ef4444', 'Rejected / dropped'],
] as const

export function PipelineLegend() {
  return (
    <div style={{ display: 'flex', gap: 18, flexWrap: 'wrap', color: '#cbd5e1', font: '600 14px Inter, sans-serif' }}>
      {items.map(([color, label]) => (
        <span key={label} style={{ alignItems: 'center', display: 'inline-flex', gap: 7 }}>
          <span style={{ background: color, borderRadius: 999, height: 9, width: 9 }} />{label}
        </span>
      ))}
    </div>
  )
}
