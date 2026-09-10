import { useId, useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import { createPortal } from 'react-dom'
import type { TimelineClip } from '../../model/sessionModel'
import { formatBytes, formatClock } from '../../views/formatters'
import type { TrafficSelection } from './trafficModel'
import { pixelAtTime, type TimeRange } from './trafficTime'
import { waveformPaths, type TrafficWaveform } from './trafficWaveform'
import type { CaptureShortfall } from './trafficCaptureQuality'

export function TrafficActivityClip({ clip, range, width, height, series, ceiling, binMs, selected, shortfall, onSelect }: {
  shortfall?: CaptureShortfall;
  clip: TimelineClip; range: TimeRange; width: number; height: number; series?: TrafficWaveform; ceiling: number; binMs: number; selected: boolean; onSelect: (selection: TrafficSelection) => void
}) {
  const tooltipId = useId()
  const [hover, setHover] = useState<{ time: number; x: number; y: number } | null>(null)
  const start = Math.max(clip.startMs, range.fromMs), end = Math.min(clip.endMs, range.toMs)
  const left = pixelAtTime(start, width, range), clipWidth = Math.max(3, pixelAtTime(end, width, range) - left)
  const showLabel = height >= 48 && clipWidth >= 180
  const chartTop = showLabel ? 18 : 2
  const chartHeight = Math.max(12, height - chartTop - 3)
  const paths = useMemo(() => {
    const plotRange = { fromMs: start, toMs: start + clipWidth / width * (range.toMs - range.fromMs) }
    return (['incoming', 'outgoing'] as const).flatMap(direction => waveformPaths(series?.bins ?? [], direction, ceiling, plotRange, clipWidth, chartHeight).map(path => ({ ...path, direction })))
  }, [series, ceiling, start, clipWidth, width, range, chartHeight])
  const hoverBin = hover ? series?.bins.find(bin => bin && bin.fromMs <= hover.time && bin.toMs > hover.time) : null
  const intervalLabel = hoverBin ? binMs < 1000 ? `${formatClock(hoverBin.fromMs)}.${String(hoverBin.fromMs % 1000).padStart(3, '0')}` : `${formatClock(hoverBin.fromMs)}–${formatClock(hoverBin.toMs)}` : formatClock(hover?.time ?? start)
  if (clip.endMs < range.fromMs || clip.startMs > range.toMs) return null
  const hasPayload = Boolean(series && (series.peakIn > 0 || series.peakOut > 0))
  const shapes = paths.map((path, i) => <g key={i} className={`wave-${path.direction} ${path.complete ? '' : 'wave-partial'}`}><path className="wave-area" d={path.area} /><path className="wave-line" d={path.line} /></g>)
  return <>
    <button type="button" className={`traffic-clip traffic-wave-clip ${selected ? 'selected' : ''} ${shortfall ? 'wave-shortfall' : ''}`} style={{ left, width: clipWidth, height, '--wave-played': `clamp(0px, calc(var(--playhead-left) - ${left}px), ${clipWidth}px)` } as CSSProperties}
      aria-pressed={selected} aria-label={`Inspect ${clip.label}, ${clip.protocol.toUpperCase()} ${clip.destinationPort}${shortfall ? ', activity detail incomplete' : ''}`} aria-describedby={hover ? tooltipId : undefined}
      onClick={() => onSelect({ kind: 'flow', id: clip.flowId, flowId: clip.flowId })}
      onPointerMove={event => { if (event.pointerType !== 'touch') setHover({ time: start + (event.clientX - event.currentTarget.getBoundingClientRect().left) / width * (range.toMs - range.fromMs), x: event.clientX, y: event.clientY }) }}
      onPointerLeave={() => setHover(null)} onBlur={() => setHover(null)}
      onFocus={event => { if (event.currentTarget.matches(':focus-visible')) { const box = event.currentTarget.getBoundingClientRect(); const peak = series?.bins.reduce((best, bin) => bin && bin.incoming + bin.outgoing > (best ? best.incoming + best.outgoing : -1) ? bin : best, null); setHover({ time: peak ? (peak.fromMs + peak.toMs) / 2 : start, x: box.left, y: box.bottom }) } }}>
      {showLabel && hasPayload && !shortfall ? <span className="wave-peak-label"><span>Peak</span><span className="incoming">↓ {formatRate(series!.peakIn)}</span><span className="outgoing">↑ {formatRate(series!.peakOut)}</span></span> : null}
      <svg className="traffic-wave-svg" width={clipWidth} height={chartHeight} style={{ top: chartTop }} viewBox={`0 0 ${clipWidth} ${chartHeight}`} aria-hidden="true">
        <defs><clipPath id={`${tooltipId}-elapsed`} clipPathUnits="userSpaceOnUse"><rect height={chartHeight} style={{ width: 'var(--wave-played)' }} /></clipPath></defs>
        <line className="wave-zero" x1="0" x2={clipWidth} y1={chartHeight / 2} y2={chartHeight / 2} />
        <g className="wave-future">{shapes}</g>
        <g className="wave-elapsed" clipPath={`url(#${tooltipId}-elapsed)`}>{shapes}</g>
      </svg>
      {shortfall ? <span className="wave-shortfall-label">{clipWidth >= 140 ? 'Activity detail incomplete' : '!'}{height >= 64 && clipWidth >= 210 ? <small>{formatBytes(shortfall.capturedBytes)} captured · {formatBytes(shortfall.totalBytes)} total</small> : null}</span> : !hasPayload && clipWidth >= 160 ? <span className="wave-empty">{series ? 'No captured payload' : 'No activity samples loaded'}</span> : null}
    </button>
    {hover ? createPortal(<div id={tooltipId} role="tooltip" className="traffic-wave-tooltip" style={{ left: Math.max(8, Math.min(hover.x + 14, window.innerWidth - 242)), top: Math.max(8, Math.min(hover.y + 18, window.innerHeight - (shortfall ? 155 : 115))) }}>
      <div>{intervalLabel}<span>{binMs / 1000}s average</span></div>
      {hoverBin ? <><p className="incoming">↓ Received <strong>{formatRate(hoverBin.incoming)}</strong></p><p className="outgoing">↑ Sent <strong>{formatRate(hoverBin.outgoing)}</strong></p><small>{hoverBin.complete && !shortfall ? 'Captured payload' : 'Captured payload · incomplete interval'}</small></> : <p>Capture unknown / samples not loaded</p>}
      {shortfall ? <small className="wave-shortfall-note">Activity detail incomplete. {formatBytes(shortfall.capturedBytes)} saved for {formatBytes(shortfall.totalBytes)} total traffic; this curve understates the transfer.</small> : null}
    </div>, document.body) : null}
  </>
}

function formatRate(rate: number) {
  if (rate > 0 && rate < .01) return '<0.01 B/s'
  return rate > 0 && rate < 10 ? `${Number(rate.toFixed(2))} B/s` : `${formatBytes(rate)}/s`
}
