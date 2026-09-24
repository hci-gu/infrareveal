import { useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { formatBytes, formatCursor } from './format'
import { TrafficDirectionControl } from './TrafficDirectionControl'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import type { DestinationVolumeIndex } from './destinationVolumes'
import { wireBars, wireWaveform, waveformCeiling } from './wireWaveform'

const ROW_HEIGHT = 88
export function MapTimeline({ data, state, onChange, index, startMs, endMs, cursorMs, onSeek, onTrack, loading, error }: {
  data: WorkspaceProjection; state: WorkspaceState; onChange: (state: WorkspaceState) => void; index: DestinationVolumeIndex
  startMs: number; endMs: number; cursorMs: number; onSeek: (time: number) => void; onTrack: (id: string) => void; loading: boolean; error: boolean
}) {
  const [scrollTop, setScrollTop] = useState(0)
  const [windowMs, setWindowMs] = useState(0)
  const [anchor, setAnchor] = useState<number | null>(null)
  const returnRef = useRef<HTMLButtonElement>(null)
  const duration = Math.max(1, endMs - startMs)
  const span = windowMs ? Math.min(windowMs, duration) : duration
  const to = Math.min(endMs, Math.max(startMs + span, anchor ?? (windowMs ? Math.floor(cursorMs / 5000) * 5000 + span / 2 : endMs)))
  const range = { from: Math.max(startMs, to - span), to }
  const first = Math.min(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 3), Math.max(0, data.rows.length - 1))
  // Bounded SVG work even for sessions containing thousands of service/location groups.
  const rows = data.rows.slice(first, first + 32)
  const signature = rows.map(row => row.connections.map(c => c.flow.id).join(',')).join('|')
  const waveforms = useMemo(() => rows.map(row => wireWaveform(row.connections, index, range)),
    // Connection identity and capture index own samples; cursor-only total changes do not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [signature, index, range.from, range.to])
  const ceiling = waveformCeiling(waveforms, state.direction)
  const progress = Math.max(0, Math.min(100, (cursorMs - range.from) / Math.max(1, range.to - range.from) * 100))
  return <section className="atlas-detail-timeline" aria-label="Traffic timeline">
    <header><div><span className="atlas-eyebrow">SAME SESSION · MORE DETAIL</span><h2>Traffic timeline</h2><p>{state.locationId ? data.locations.find(l => l.id === state.locationId)?.label ?? 'Location no longer retained' : 'All locations'} · grouped by service and remote location</p></div><button type="button" ref={returnRef} autoFocus onClick={() => onChange({ ...state, expanded: false })}>↙ Back to map</button></header>
    <div className="atlas-mobile-timeline-filters"><TrafficDirectionControl value={state.direction} onChange={direction => onChange({ ...state, direction })} />{state.locationId && <button type="button" onClick={() => onChange({ ...state, locationId: null })}>Clear location ×</button>}</div>
    <div className="atlas-timeline-options"><span className="atlas-down">↓ Downloaded above</span><span className="atlas-up">↑ Sent below</span><label>Window <select aria-label="Timeline window" value={windowMs} onChange={event => { setWindowMs(Number(event.target.value)); setAnchor(null) }}><option value={0}>Retained window</option><option value={30_000}>30 seconds</option><option value={300_000}>5 minutes</option><option value={1_800_000}>30 minutes</option></select></label></div>
    <div className="atlas-wave-quality" role="status">{loading ? 'Loading capture…' : error ? 'Capture unavailable · retrying' : `Captured wire rate · interval averages · shown tracks share a ${formatBytes(ceiling)}/s scale. Dashed outlines = partial; gaps = no capture.`}</div>
    <div className="atlas-detail-ruler"><span>Service / location</span><div>{Array.from({ length: 5 }, (_, i) => <span key={i}>{formatCursor(range.from + (range.to - range.from) * i / 4)}</span>)}</div></div>
    <div className="atlas-detail-scroll" onScroll={event => setScrollTop(event.currentTarget.scrollTop)}>
      <div style={{ height: data.rows.length * ROW_HEIGHT, position: 'relative' }}>
        {rows.map((row, i) => {
          const bins = waveforms[i]
          const hasCapture = bins.some(bin => bin.observed)
          return <div className="atlas-detail-row" key={row.id} style={{ top: (first + i) * ROW_HEIGHT, '--playhead': `${progress}%` } as CSSProperties} data-timeline-location={row.locationId}>
            <button type="button" className="atlas-detail-track" onClick={() => onTrack(row.trackId)} title={`${row.label} · ${row.client} · ${row.connections.length} connections`}><strong>{row.label}</strong><small>{row.location} · {row.client}</small><span>{state.direction !== 'sent' && <span className="atlas-down">↓ {loading || error ? '—' : formatBytes(row.received)}</span>}{state.direction !== 'received' && <span className="atlas-up">↑ {loading || error ? '—' : formatBytes(row.sent)}</span>}</span></button>
            <div className="atlas-detail-lane"><svg viewBox="0 0 1000 64" preserveAspectRatio="none" aria-hidden="true"><line x1="0" y1="32" x2="1000" y2="32" className="atlas-wave-zero" />{!loading && !error && (['received', 'sent'] as const).filter(direction => state.direction === 'both' || state.direction === direction).flatMap(direction => wireBars(bins, direction, ceiling).map((bar, j) => <rect key={`${direction}-${j}`} x={bar.x} y={direction === 'received' ? 32 - bar.height : 32} width={bar.width} height={bar.height} className={`atlas-wave-${direction}${bar.partial ? ' is-partial' : ''}`} />))}</svg>
              {(!hasCapture || loading || error) && <span className="atlas-no-capture">{loading ? 'Loading…' : error ? 'Capture unavailable' : 'No captured samples'}</span>}
              <i className="atlas-detail-playhead" /><input type="range" aria-label={`Seek ${row.label} timeline`} aria-valuetext={formatCursor(cursorMs)} min={range.from} max={Math.max(range.from + 1, range.to)} step={100} value={Math.max(range.from, Math.min(range.to, cursorMs))} onChange={event => onSeek(Number(event.target.value))} />
            </div>
          </div>
        })}
      </div>{data.rows.length === 0 && <p className="atlas-list-empty">No traffic in this selection at the playhead. Clear the location filter or move forward in time.</p>}
    </div><footer><button type="button" disabled={range.from <= startMs} onClick={() => setAnchor(Math.max(startMs + span, to - span / 2))}>← Earlier</button><span>Totals are wire bytes to the playhead · {data.rows.length} tracks</span><button type="button" disabled={range.to >= endMs} onClick={() => setAnchor(Math.min(endMs, to + span / 2))}>Later →</button></footer>
  </section>
}
