import { useLiveList } from './useLiveList'
import { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { formatBytes, formatCursor } from './format'
import { TrafficDirectionControl } from './TrafficDirectionControl'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import type { DestinationVolumeIndex } from './destinationVolumes'
import { wireFlows, wireGaps, createWireWaveformCache, waveformCeiling, waveformGrid } from './wireWaveform'
import { timelineLanes } from './timelineLanes'

const ROW_HEIGHT = 104
export function MapTimeline({ data, state, onChange, index, detailIndex, startMs, endMs, cursorMs, onSeek, onTrack, loading, error, refreshing, live, following, onFollowLive }: {
  data: WorkspaceProjection; state: WorkspaceState; onChange: (state: WorkspaceState) => void; index: DestinationVolumeIndex; detailIndex?: DestinationVolumeIndex
  startMs: number; endMs: number; cursorMs: number; onSeek: (time: number) => void; onTrack: (id: string) => void; loading: boolean; error: boolean; refreshing: boolean
  live: boolean; following: boolean; onFollowLive: () => void
}) {
  const [showAll, setShowAll] = useState(false)
  const [scrollTop, setScrollTop] = useState(0)
  const [windowMs, setWindowMs] = useState(300_000)
  const [anchor, setAnchor] = useState<number | null>(null)
  const [scale, setScale] = useState({ scope: '', ceiling: 0 })
  const scrollElement = useRef<HTMLDivElement>(null)
  const gradientId = useId()
  const scope = JSON.stringify([data.scene.sessionId, state.direction, state.locationId, state.order, windowMs, showAll])
  const [previousScope, setPreviousScope] = useState(scope)
  if (previousScope !== scope) { setPreviousScope(scope); setScrollTop(0); setAnchor(null) }
  useEffect(() => { scrollElement.current?.scrollTo({ top: 0, left: 0 }) }, [scope])

  const duration = Math.max(1, endMs - startMs)
  const span = windowMs ? Math.min(windowMs, duration) : duration
  const to = Math.min(endMs, Math.max(startMs + span, anchor ?? (windowMs ? cursorMs : endMs)))
  const range = { from: Math.max(startMs, to - span), to }
  // Use the fine capture already loaded for the map whenever it covers this view.
  const capture = detailIndex && (detailIndex.fromMs ?? Infinity) <= range.from && (detailIndex.toMs ?? 0) >= range.to ? detailIndex : index
  const grid = waveformGrid(range, 240)
  const lanes = timelineLanes(data.rows, capture, range, cursorMs, state.direction)
  const active = lanes.filter(row => row.windowBytes > 0).sort((a, b) => b.windowLastActivityMs - a.windowLastActivityMs || b.windowBytes - a.windowBytes || a.id.localeCompare(b.id))
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, pause: pauseList } = useLiveList(showAll ? lanes : active, scope, cursorMs)
  const first = Math.min(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 3), Math.max(0, orderedItems.length - 1))
  const rows = orderedItems.slice(first, first + 32)
  const waveform = useMemo(() => createWireWaveformCache(), [])
  const signature = data.rows.map(row => row.series.map(c => [c.id, c.startMs, c.endMs].join(':')).join(',')).join('|')
  const waveforms = useMemo(() => new Map(data.rows.map(row => [row.id, waveform(row.series, capture, grid, grid.count)])),
    // Capture identity and series boundaries own samples; cursor-only totals do not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [waveform, signature, capture, grid.from, grid.to, grid.count])
  const scaleScope = JSON.stringify([data.scene.sessionId, state.direction, state.locationId, windowMs, grid.binMs])
  const ceiling = waveformCeiling([...waveforms.values()], state.direction, scale.scope === scaleScope ? scale.ceiling : 0)
  if (scale.scope !== scaleScope || scale.ceiling !== ceiling) setScale({ scope: scaleScope, ceiling })
  const svgFrom = (range.from - grid.from) / (grid.to - grid.from) * 1000
  const svgWidth = (range.to - range.from) / (grid.to - grid.from) * 1000
  const progress = Math.max(0, Math.min(100, (cursorMs - range.from) / Math.max(1, range.to - range.from) * 100))
  const held = anchor !== null || listPaused
  const hold = () => { setAnchor(range.to); pauseList() }
  const follow = () => { setAnchor(null); setShowAll(false); setScrollTop(0); resumeList(); if (live) onFollowLive() }
  const directions = (['received', 'sent'] as const).filter(direction => state.direction === 'both' || state.direction === direction)

  return <section className="atlas-detail-timeline" aria-label="Traffic timeline" style={{ '--timeline-row-height': `${ROW_HEIGHT}px` } as CSSProperties} data-scale-ceiling={ceiling} data-bin-ms={grid.binMs} data-window-from={range.from} data-window-to={range.to} data-visible-lanes={orderedItems.length}>
    <header><div><span className="atlas-eyebrow">TRAFFIC IN MOTION</span><h2>Traffic timeline</h2><p>{state.locationId ? data.locations.find(l => l.id === state.locationId)?.label ?? 'Location no longer retained' : 'All locations'} · one lane per endpoint</p></div><button type="button" autoFocus onClick={() => onChange({ ...state, expanded: false })}>↙ Back to map</button></header>
    <div className="atlas-mobile-timeline-filters"><TrafficDirectionControl value={state.direction} onChange={direction => onChange({ ...state, direction })} />{state.locationId && <button type="button" onClick={() => onChange({ ...state, locationId: null })}>Clear location ×</button>}</div>
    <div className="atlas-timeline-toolbar">
      <div className="atlas-segmented" aria-label="Timeline lanes"><button type="button" aria-pressed={!showAll} onClick={() => setShowAll(false)}>Recent activity <small>{active.length}</small></button><button type="button" aria-pressed={showAll} onClick={() => setShowAll(true)}>All lanes <small>{lanes.length}</small></button></div>
      <span className={`atlas-timeline-follow-state${!held && following ? ' is-live' : ''}`}><i />{held ? 'Window held' : live && following ? 'Following live' : 'Following playhead'}</span>
      <button type="button" className="atlas-timeline-follow" onClick={follow}>{live ? 'Follow live' : 'Follow playhead'} ↗</button>
    </div>
    <div className="atlas-timeline-options"><span className="atlas-down">↓ Downloaded</span><span className="atlas-up">↑ Sent</span><button type="button" onClick={() => setScale({ scope: scaleScope, ceiling: waveformCeiling([...waveforms.values()], state.direction) })} title="Refit flow thickness to the current window">Fit scale</button><label>Window <select aria-label="Timeline window" value={windowMs} onChange={event => setWindowMs(Number(event.target.value))}><option value={30_000}>30 seconds</option><option value={300_000}>5 minutes</option><option value={1_800_000}>30 minutes</option><option value={0}>Loaded history</option></select></label></div>
    <div className="atlas-wave-quality" role="status">{refreshing ? 'Updating · showing last loaded capture' : loading ? 'Loading capture…' : error ? 'Capture unavailable · retrying' : `${showAll ? 'All endpoints' : `${active.filter(row => row.recentlyActive).length} active in last 30s · newest first, quiet lanes fade`} · ${grid.binMs / 1000}s averages · shared square-root scale to ${formatBytes(ceiling)}/s. Dashed flows = partial; hatching = no capture.`}</div>
    <svg className="atlas-flow-definitions" aria-hidden="true"><defs><pattern id={`${gradientId}-gap`} width="7" height="7" patternUnits="userSpaceOnUse"><path d="M0,7 L7,0" className="atlas-capture-gap" /></pattern>{(['received', 'sent'] as const).map(direction => <linearGradient key={direction} id={`${gradientId}-${direction}`} x1="0" y1="0" x2="0" y2="1" className={`atlas-flow-${direction}`}><stop offset="0" stopColor="currentColor" stopOpacity=".35" /><stop offset=".45" stopColor="currentColor" stopOpacity=".95" /><stop offset=".5" stopColor="currentColor" /><stop offset="1" stopColor="currentColor" stopOpacity=".25" /></linearGradient>)}</defs></svg>
    <div className="atlas-detail-ruler"><span>Service / endpoint</span><div>{Array.from({ length: 5 }, (_, i) => <span key={i}>{formatCursor(range.from + (range.to - range.from) * i / 4)}</span>)}</div></div>
    <div ref={element => { listRef(element); scrollElement.current = element }} className="atlas-detail-scroll" onFocusCapture={hold} onScroll={event => { scrollList(event); setScrollTop(event.currentTarget.scrollTop); if (event.currentTarget.scrollTop > 8) hold() }}>
      <div style={{ height: orderedItems.length * ROW_HEIGHT, position: 'relative' }}>
        {rows.map((row, i) => {
          const bins = waveforms.get(row.id) ?? []
          const hasCapture = bins.some(bin => bin.observed)
          return <div className={`atlas-detail-row${row.recentlyActive ? ' is-active' : ''}`} key={row.id} style={{ '--lane-y': `${(first + i) * ROW_HEIGHT}px`, '--lane-opacity': row.activityOpacity, '--playhead': `${progress}%` } as CSSProperties} data-timeline-location={row.locationId} data-timeline-series={row.id}>
            <button type="button" className="atlas-detail-track" onClick={() => onTrack(row.trackId)} title={`${row.label} · ${row.endpoint} · ${row.client}`}><strong>{row.label}</strong><small>{row.endpoint}</small><small>{row.location} · {row.client}</small><span>{state.direction !== 'sent' && <span className="atlas-down">↓ {loading || error ? '—' : formatBytes(row.received)}</span>}{state.direction !== 'received' && <span className="atlas-up">↑ {loading || error ? '—' : formatBytes(row.sent)}</span>}</span></button>
            <div className="atlas-detail-lane"><svg viewBox={`${svgFrom} 0 ${svgWidth} 64`} preserveAspectRatio="none" aria-hidden="true">
              {!loading && !error && wireGaps(bins).map(gap => <rect key={gap.x} x={gap.x} y={0} width={gap.width} height={64} fill={`url(#${gradientId}-gap)`} />)}
              {directions.map(direction => <line key={direction} x1="0" y1={direction === 'received' ? 17 : 47} x2="1000" y2={direction === 'received' ? 17 : 47} className="atlas-wave-zero" />)}
              {!loading && !error && directions.flatMap(direction => wireFlows(bins, direction, ceiling).map((flow, j) => <g key={`${direction}-${j}`} className={`atlas-flow-${direction}${flow.partial ? ' is-partial' : ''}`}><path className="atlas-flow-envelope" d={flow.path} fill={`url(#${gradientId}-${direction})`} /><path className="atlas-flow-center" d={flow.center} /></g>))}
            </svg>
              {(!hasCapture || loading || error || !row.windowBytes) && <span className="atlas-no-capture">{loading ? 'Loading…' : error ? 'Capture unavailable' : !hasCapture ? 'No captured samples' : 'No traffic in this window'}</span>}
              <i className="atlas-detail-playhead" /><input type="range" aria-label={`Seek ${row.label} ${row.endpoint} timeline`} aria-valuetext={formatCursor(cursorMs)} min={range.from} max={Math.max(range.from + 1, range.to)} step={50} value={Math.max(range.from, Math.min(range.to, cursorMs))} onChange={event => onSeek(Number(event.target.value))} />
            </div>
          </div>
        })}
      </div>{orderedItems.length === 0 && <div className="atlas-timeline-empty"><strong>{loading ? 'Loading traffic…' : error ? 'Capture unavailable' : refreshing ? 'Updating traffic…' : 'No traffic in this window'}</strong><p>{loading || error || refreshing ? 'Captured traffic will appear when available.' : 'Waiting for activity. Browse earlier traffic or show all lanes to inspect quiet endpoints.'}</p>{!showAll && <button type="button" onClick={() => setShowAll(true)}>Show all {lanes.length} lanes</button>}</div>}
    </div><footer><button type="button" disabled={range.from <= startMs} onClick={() => { setAnchor(Math.max(startMs + span, to - span / 2)); pauseList() }}>← Earlier</button><span>{orderedItems.length} of {data.rows.length} lanes · totals to playhead</span><button type="button" disabled={range.to >= endMs} onClick={() => { setAnchor(Math.min(endMs, to + span / 2)); pauseList() }}>Later →</button></footer>
  </section>
}
