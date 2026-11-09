import { memo } from 'react'
import { WIRE_FLOW_HEIGHT, wireFlows, wireGaps } from './wireWaveform'
import type { WireBin } from './wireWaveform'

/** Geometry changes with captured samples, never with the animation clock.
 * Separate SVG subpaths preserve silence/gaps without a React node per burst. */
export const TimelineFlows = memo(function TimelineFlows({ bins, ceiling, gradientId, available }: {
  bins: WireBin[]; ceiling: number; gradientId: string; available: boolean
}) {
  const directions = ['received', 'sent'] as const
  return <div className="atlas-flow-viewport"><svg viewBox={`0 0 1000 ${WIRE_FLOW_HEIGHT}`} preserveAspectRatio="none" aria-hidden="true">
    {available && wireGaps(bins).map(gap => <rect key={gap.x} x={gap.x} y={0} width={gap.width} height={WIRE_FLOW_HEIGHT} fill={`url(#${gradientId}-gap)`} />)}
    {available && directions.flatMap(value => {
      const flows = wireFlows(bins, value, ceiling)
      return [false, true].flatMap(partial => {
        const measured = flows.filter(flow => flow.partial === partial)
        return measured.length ? <g key={`${value}-${partial}`} className={`atlas-flow-${value}${partial ? ' is-partial' : ''}`}>
          <path className="atlas-flow-envelope" d={measured.map(flow => flow.path).join(' ')} fill={`url(#${gradientId}-${value})`} />
        </g> : []
      })
    })}
    <line x1="0" y1={WIRE_FLOW_HEIGHT / 2} x2="1000" y2={WIRE_FLOW_HEIGHT / 2} className="atlas-wave-zero" />
  </svg></div>
})
