import { useMemo, useRef, useState } from 'react'
import type { PointerEvent } from 'react'
import { formatBytes } from './format'
import type { WorkspaceProjection } from './mapWorkspace'
import { directionPoints, logDomain, sendRatio, tickLabel } from './directionPoints'
import type { DirectionPoint } from './directionPoints'

const W = 300, H = 268
const M = { left: 46, right: 10, top: 10, bottom: 34 }
const PW = W - M.left - M.right, PH = H - M.top - M.bottom
const HIT = 14
const LABELS = 3
/** Within 5% either way is "about even" and stays neutral. */
const EVEN = 1.05
const LABEL_MIN_SENT = 1_000
const lean = (point: DirectionPoint) => point.sent > point.received * EVEN ? 'sent' : point.received > point.sent * EVEN ? 'received' : 'even'

/** Sent against downloaded bytes per service on shared log axes. Points above
 * the diagonal sent more than they received. */
export function DirectionScatter({ data, loading }: { data: WorkspaceProjection; loading: boolean }) {
  const points = useMemo(() => directionPoints(data.bySeries.values(), data.volumeBySeries), [data.bySeries, data.volumeBySeries])
  const [lo, hi] = useMemo(() => logDomain(points), [points])
  const scale = (value: number) => (Math.log10(Math.max(lo, Math.min(hi, value))) - Math.log10(lo)) / (Math.log10(hi) - Math.log10(lo))
  const x = (value: number) => M.left + scale(value) * PW
  const y = (value: number) => M.top + (1 - scale(value)) * PH
  const ticks: number[] = []
  for (let value = lo; value <= hi * 1.0001; value *= 10) ticks.push(value)
  const svgRef = useRef<SVGSVGElement>(null)
  const [active, setActive] = useState<string | null>(null)
  const focused = points.find(point => point.id === active)
  const senders = points.filter(point => lean(point) === 'sent')
  const labelled = useMemo(() => directLabels(points, x, y), [points, lo, hi]) // eslint-disable-line react-hooks/exhaustive-deps

  const onMove = (event: PointerEvent<SVGSVGElement>) => {
    const svg = svgRef.current, matrix = svg?.getScreenCTM()
    if (!svg || !matrix) return
    const local = new DOMPoint(event.clientX, event.clientY).matrixTransform(matrix.inverse())
    let best: DirectionPoint | null = null, distance = HIT
    for (const point of points) {
      const d = Math.hypot(x(point.received) - local.x, y(point.sent) - local.y)
      if (d < distance) { best = point; distance = d }
    }
    setActive(best?.id ?? null)
  }

  return <section className="atlas-insight" aria-labelledby="direction-title">
    <h3 id="direction-title">Who listens more than they talk</h3>
    <p className="atlas-insight-help">Each dot is a service. Above the line, your devices sent it more than they downloaded.</p>
    {!points.length ? <p className="atlas-insight-empty">{loading ? 'Loading services…' : 'No traffic in this window.'}</p> : <>
      <svg ref={svgRef} className="atlas-direction" viewBox={`0 0 ${W} ${H}`} role="img"
        aria-label={`${senders.length} of ${points.length} services sent more than they received`}
        onPointerMove={onMove} onPointerLeave={() => setActive(null)}>
        <path className="atlas-direction-zone" d={`M${M.left} ${M.top}H${M.left + PW}L${M.left} ${M.top + PH}Z`} />
        {ticks.map(tick => <g key={tick} className="atlas-direction-grid">
          <line x1={x(tick)} x2={x(tick)} y1={M.top} y2={M.top + PH} />
          <line x1={M.left} x2={M.left + PW} y1={y(tick)} y2={y(tick)} />
          <text x={x(tick)} y={M.top + PH + 14} textAnchor="middle">{tickLabel(tick)}</text>
          <text x={M.left - 6} y={y(tick)} textAnchor="end" dominantBaseline="middle">{tickLabel(tick)}</text>
        </g>)}
        <line className="atlas-direction-diagonal" x1={x(lo)} y1={y(lo)} x2={x(hi)} y2={y(hi)} />
        <text className="atlas-direction-zone-label" x={M.left + 8} y={M.top + 14}>Sends more</text>
        <text className="atlas-direction-zone-label" x={M.left + PW - 8} y={M.top + PH - 8} textAnchor="end">Downloads more</text>
        <text className="atlas-direction-axis" x={M.left + PW / 2} y={H - 4} textAnchor="middle">↓ Downloaded</text>
        <text className="atlas-direction-axis" transform={`translate(10 ${M.top + PH / 2}) rotate(-90)`} textAnchor="middle">↑ Sent</text>
        {points.map(point => <circle key={point.id} className="atlas-direction-dot" data-direction={lean(point)}
          data-dimmed={active && active !== point.id ? true : undefined} cx={x(point.received)} cy={y(point.sent)} r={4.5} />)}
        {labelled.filter(label => label.id !== active).map(label => <text key={label.id} className="atlas-direction-label" x={label.x} y={label.y} textAnchor={label.anchor} dominantBaseline="middle">{label.text}</text>)}
        {focused && <circle className="atlas-direction-focus" cx={x(focused.received)} cy={y(focused.sent)} r={7.5} />}
      </svg>
      <p className="atlas-word-cloud-caption" aria-live="polite">{focused
        ? <><strong>{focused.label}</strong> · ↓ {formatBytes(focused.received)} · ↑ {formatBytes(focused.sent)} · {ratioText(focused)}</>
        : <>{senders.length} of {points.length} {points.length === 1 ? 'service' : 'services'} sent more than they downloaded</>}</p>
      <table className="atlas-sr-only"><caption>Bytes sent and downloaded per service</caption>
        <thead><tr><th scope="col">Service</th><th scope="col">Downloaded</th><th scope="col">Sent</th></tr></thead>
        <tbody>{points.map(point => <tr key={point.id}><th scope="row">{point.label}</th><td>{formatBytes(point.received)}</td><td>{formatBytes(point.sent)}</td></tr>)}</tbody>
      </table>
    </>}
  </section>
}

function ratioText(point: DirectionPoint) {
  const ratio = sendRatio(point)
  if (!Number.isFinite(ratio)) return 'only sent'
  if (point.sent === 0) return 'only downloaded'
  if (ratio >= EVEN) return `sent ${ratio >= 10 ? Math.round(ratio) : ratio.toFixed(1)}× more`
  if (ratio <= 1 / EVEN) return `downloaded ${1 / ratio >= 10 ? Math.round(1 / ratio) : (1 / ratio).toFixed(1)}× more`
  return 'about even'
}

/** Name the strongest senders directly, skipping any label that would collide. */
function directLabels(points: DirectionPoint[], x: (v: number) => number, y: (v: number) => number) {
  const boxes = points.map(point => ({ x0: x(point.received) - 6, x1: x(point.received) + 6, y0: y(point.sent) - 6, y1: y(point.sent) + 6 }))
  const labels: { id: string; text: string; x: number; y: number; anchor: 'start' | 'end' }[] = []
  const candidates = points.filter(point => point.sent >= LABEL_MIN_SENT && point.sent > point.received * 1.5).sort((a, b) => sendRatio(b) - sendRatio(a) || b.sent - a.sent)
  for (const point of candidates) {
    if (labels.length >= LABELS) break
    const width = point.label.length * 5.6
    const px = x(point.received), py = y(point.sent)
    // Prefer the right of the dot, then the left; never over a dot or the axes.
    for (const anchor of ['start', 'end'] as const) {
      const box = anchor === 'start' ? { x0: px + 7, x1: px + 8 + width, y0: py - 6, y1: py + 6 } : { x0: px - 8 - width, x1: px - 7, y0: py - 6, y1: py + 6 }
      if (box.x0 < M.left || box.x1 > W - M.right || box.y0 < M.top || box.y1 > M.top + PH || boxes.some(o => box.x0 < o.x1 && box.x1 > o.x0 && box.y0 < o.y1 && box.y1 > o.y0)) continue
      boxes.push(box)
      labels.push({ id: point.id, text: point.label, x: anchor === 'start' ? px + 8 : px - 8, y: py, anchor })
      break
    }
  }
  return labels
}
