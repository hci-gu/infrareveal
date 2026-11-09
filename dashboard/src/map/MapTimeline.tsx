import { useLiveList } from './useLiveList'
import { useEffect, useId, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { formatBytes, formatCursor } from './format'
import { DEFAULT_TRAFFIC_FILTERS, filterScope } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import type { DestinationVolumeIndex } from './destinationVolumes'
import { createWireWaveformCache, waveformCeiling, timelineWaveformGrid } from './wireWaveform'
import { timelineLanes } from './timelineLanes'
import type { MapPlaybackClock } from './mapPlaybackClock'
import { timelineRange, useTimelineViewport } from './useTimelineViewport'
import { TimelineFlows } from './TimelineFlows'

const ROW_HEIGHT = 72
export function MapTimeline({ data, state, index, detailIndex, startMs, endMs, cursorMs, onSeek, onTrack, loading, error, refreshing, live, navigationRevision = 0, clock, playbackEpochMs = startMs }: {
  data: WorkspaceProjection; state: WorkspaceState; index: DestinationVolumeIndex; detailIndex?: DestinationVolumeIndex
  startMs: number; endMs: number; cursorMs: number; onSeek: (time: number) => void; onTrack: (id: string) => void; loading: boolean; error: boolean; refreshing: boolean
  live: boolean; navigationRevision?: number
  clock?: MapPlaybackClock; playbackEpochMs?: number
}) {
  const [scrollTop, setScrollTop] = useState(0)
  const windowMs = state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs
  const [anchor, setAnchor] = useState<number | null>(null)
  const [scale, setScale] = useState({ scope: '', ceiling: 0 })
  const scrollElement = useRef<HTMLDivElement>(null)
  const gradientId = useId()
  // Explicit navigation in the shared player releases browsing holds. Live
  // clock corrections and incoming data leave the inspected window alone.
  const scope = JSON.stringify([data.scene.sessionId, filterScope(state), state.order, navigationRevision])
  const [previousScope, setPreviousScope] = useState(scope)
  if (previousScope !== scope) { setPreviousScope(scope); setScrollTop(0); setAnchor(null) }
  useEffect(() => { scrollElement.current?.scrollTo({ top: 0, left: 0 }) }, [scope])

  const range = timelineRange(startMs, endMs, cursorMs, windowMs, anchor, live)
  const to = range.to, span = range.to - range.from
  // Use the fine capture already loaded for the map whenever it covers this view.
  const capture = detailIndex && (detailIndex.fromMs ?? Infinity) <= range.from && (detailIndex.toMs ?? 0) >= range.to ? detailIndex : index
  const grid = timelineWaveformGrid(range, windowMs)
  const { ref: viewportRef, currentRange } = useTimelineViewport({ clock, epochMs: playbackEpochMs, cursorMs, startMs, endMs, windowMs, anchor, live, grid })
  const lanes = timelineLanes(data.rows, capture, range, cursorMs)
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, onScroll: scrollList, pause: pauseList } = useLiveList(lanes, scope, Math.min(range.to, cursorMs), state.order === 'latest' ? row => row.windowLastActivityMs : undefined)
  const first = Math.min(Math.max(0, Math.floor(scrollTop / ROW_HEIGHT) - 3), Math.max(0, orderedItems.length - 1))
  const rows = orderedItems.slice(first, first + 32)
  const waveform = useMemo(() => createWireWaveformCache(), [])
  const signature = JSON.stringify(data.rows.map(row => [row.id, row.series.map(c => c.id)]))
  const waveforms = useMemo(() => new Map(data.rows.map(row => [row.id, waveform(row.series, capture, grid, grid.count)])),
    // Capture identity and lane membership own samples; cursor-only totals do not.
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [waveform, signature, capture, grid.from, grid.to, grid.count])
  const scaleScope = JSON.stringify([data.scene.sessionId, filterScope(state), grid.binMs])
  const ceiling = waveformCeiling([...waveforms.values()], scale.scope === scaleScope ? scale.ceiling : 0)
  if (scale.scope !== scaleScope || scale.ceiling !== ceiling) setScale({ scope: scaleScope, ceiling })
  const held = anchor !== null || listPaused
  const hold = () => { setAnchor(currentRange().to); pauseList() }

  return <section ref={viewportRef} className="atlas-detail-timeline" aria-label="Traffic timeline" style={{ '--timeline-row-height': `${ROW_HEIGHT}px` } as CSSProperties} data-held={held || undefined} aria-busy={loading || refreshing} data-scale-ceiling={ceiling} data-bin-ms={grid.binMs} data-grid-from={grid.from} data-grid-to={grid.to} data-window-from={range.from} data-window-to={range.to} data-visible-lanes={orderedItems.length}>
    <svg className="atlas-flow-definitions" aria-hidden="true"><defs><pattern id={`${gradientId}-gap`} width="7" height="7" patternUnits="userSpaceOnUse"><path d="M0,7 L7,0" className="atlas-capture-gap" /></pattern>{(['received', 'sent'] as const).map(direction => <linearGradient key={direction} id={`${gradientId}-${direction}`} x1="0" y1={direction === 'received' ? "1" : "0"} x2="0" y2={direction === 'received' ? "0" : "1"} className={`atlas-flow-${direction}`}><stop offset="0" stopColor="currentColor" stopOpacity=".9" /><stop offset="1" stopColor="currentColor" stopOpacity=".3" /></linearGradient>)}</defs></svg>
    <div className="atlas-detail-ruler"><span>Service</span><div>{Array.from({ length: 5 }, (_, i) => <span key={i}>{formatCursor(range.from + (range.to - range.from) * i / 4)}</span>)}</div></div>
    <div ref={element => { listRef(element); scrollElement.current = element }} className="atlas-detail-scroll" onFocusCapture={hold} onScroll={event => { scrollList(event); setScrollTop(event.currentTarget.scrollTop); if (event.currentTarget.scrollTop > 8) hold() }}>
      <div style={{ height: orderedItems.length * ROW_HEIGHT, position: 'relative' }}>
        {rows.map((row, i) => {
          const bins = waveforms.get(row.id) ?? []
          const hasCapture = bins.some(bin => bin.observed)
          return <div className={`atlas-detail-row${row.recentlyActive ? ' is-active' : ''}`} key={row.id} style={{ '--lane-y': `${(first + i) * ROW_HEIGHT}px`, '--lane-opacity': row.activityOpacity } as CSSProperties} data-timeline-location={row.locationId} data-timeline-series={row.id}>
            <button type="button" className="atlas-detail-track" onClick={() => onTrack(row.trackId)} title={`${row.label} · ${row.endpoint} · ${row.client}`}><strong>{row.label}</strong><small>{row.location} · {row.client}</small><span><span className="atlas-down">↓ {loading || error ? '—' : formatBytes(row.received)}</span><span className="atlas-up">↑ {loading || error ? '—' : formatBytes(row.sent)}</span></span></button>
            <div className="atlas-detail-lane"><TimelineFlows bins={bins} ceiling={ceiling} gradientId={gradientId} available={!loading && !error} />
              {(!hasCapture || loading || error || !row.windowBytes) && <span className="atlas-no-capture">{loading ? 'Loading…' : error ? 'Capture unavailable' : !hasCapture ? 'No captured samples' : 'No traffic in this window'}</span>}
              <i className="atlas-detail-playhead" /><input type="range" aria-label={`Seek ${row.label} ${row.endpoint} timeline`} aria-valuetext={formatCursor(cursorMs)} min={range.from} max={Math.max(range.from + 1, range.to)} step={50} value={Math.max(range.from, Math.min(range.to, cursorMs))} onChange={event => onSeek(Number(event.target.value))} />
            </div>
          </div>
        })}
      </div>{orderedItems.length === 0 && <div className="atlas-timeline-empty"><strong>{loading ? 'Loading traffic…' : error ? 'Capture unavailable' : refreshing ? 'Updating traffic…' : 'No traffic in this window'}</strong><p>{loading || error || refreshing ? 'Captured traffic will appear when available.' : 'No matching traffic. Adjust the Filters panel or browse earlier traffic.'}</p></div>}
    </div><footer><button type="button" disabled={range.from <= startMs} onClick={() => { setAnchor(Math.max(startMs + span, to - span / 2)); pauseList() }}>← Earlier</button><span>{orderedItems.length} {orderedItems.length === 1 ? 'lane' : 'lanes'} · totals to playhead</span><button type="button" disabled={range.to >= endMs} onClick={() => { setAnchor(Math.min(endMs, to + span / 2)); pauseList() }}>Later →</button></footer>
  </section>
}
