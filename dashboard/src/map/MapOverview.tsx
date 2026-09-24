import { useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { formatBytes, formatCursor } from './format'
import { MapIcon } from './MapIcon'
import { MapTrackList } from './MapTrackList'
import { TrafficDirectionControl } from './TrafficDirectionControl'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import { directionLabel } from './mapWorkspace'

export function MapOverview({ data, state, onChange, startMs, cursorMs, loading, error, selectedTrack, onTrack, activeOnly, onActiveOnly }: {
  data: WorkspaceProjection; state: WorkspaceState; onChange: (value: WorkspaceState) => void; startMs: number; cursorMs: number; loading: boolean; error: boolean
  selectedTrack: string | null; onTrack: (id: string | null) => void; activeOnly: boolean; onActiveOnly: (value: boolean) => void
}) {
  const [tab, setTab] = useState<'locations' | 'tracks'>('locations')
  const [dragWidth, setDragWidth] = useState<number | null>(null)
  const [snap, setSnap] = useState(false)
  const drag = useRef<{ start: number; width: number; limit: number } | null>(null)
  const aside = useRef<HTMLElement>(null)
  const peak = Math.max(1, ...data.locations.map(location => location.bytes))
  const location = data.locations.find(location => location.id === state.locationId)
  const quality = loading ? 'Loading totals…' : error ? 'Totals unavailable · retrying' : data.total.estimated ? '≈ Includes counter estimates' : data.total.partial ? 'Captured wire bytes · partial' : 'Captured wire bytes'
  return <aside ref={aside} className="atlas-overview atlas-workspace-overview" aria-label="Traffic overview" style={dragWidth ? { '--overview-width': `${dragWidth}px` } as CSSProperties : undefined}>
    <div className="atlas-overview-heading"><h1>Traffic overview</h1><button type="button" className="atlas-icon-button" aria-label={state.expanded ? 'Back to map' : 'Expand traffic timeline'} onClick={() => onChange({ ...state, expanded: !state.expanded })}><MapIcon name={state.expanded ? 'back' : 'expand'} size={17} /></button></div>
    <p className="atlas-scope">{formatCursor(startMs)}–{formatCursor(cursorMs)} UTC</p>
    <TrafficDirectionControl value={state.direction} onChange={direction => onChange({ ...state, direction })} />
    {state.locationId && <button type="button" className="atlas-clear-location" onClick={() => onChange({ ...state, locationId: null })}>{location?.label ?? 'Location no longer retained'} ×</button>}
    <div className="atlas-metrics atlas-direction-metrics">
      <div className={`atlas-down ${state.direction === 'sent' ? 'is-inactive' : ''}`}><span className="atlas-metric-label">↓ Downloaded</span><strong data-direction-total="received">{loading || error ? '—' : formatBytes(data.total.received)}</strong></div>
      <div className={`atlas-up ${state.direction === 'received' ? 'is-inactive' : ''}`}><span className="atlas-metric-label">↑ Sent</span><strong data-direction-total="sent">{loading || error ? '—' : formatBytes(data.total.sent)}</strong></div>
    </div><p className="atlas-quality" role="status">{quality} · to playhead</p>
    <div className="atlas-overview-tabs" aria-label="Overview content"><button type="button" aria-pressed={tab === 'locations'} onClick={() => setTab('locations')}>Locations <small>{data.locations.length}</small></button><button type="button" aria-pressed={tab === 'tracks'} onClick={() => setTab('tracks')}>Tracks <small>{data.tracks.length}</small></button></div>
    {tab === 'locations' ? <div className="atlas-location-list" aria-label="Remote locations"><div className="atlas-location-sort">By {directionLabel(state.direction).toLowerCase()}</div>{data.locations.map(location => <button type="button" key={location.id} className="atlas-location-row" aria-pressed={state.locationId === location.id} data-location-id={location.id} onClick={() => onChange({ ...state, locationId: state.locationId === location.id ? null : location.id })}>
      <span>{location.label}</span><strong>{loading || error ? '—' : `${location.estimated ? '≈ ' : ''}${formatBytes(location.bytes)}`}</strong><small>{location.detail}</small>
      <span className="atlas-location-bars" aria-hidden="true">{state.direction !== 'sent' && <i className="atlas-down-bar" style={{ width: `${location.received / peak * 100}%` }} />}{state.direction !== 'received' && <i className="atlas-up-bar" style={{ width: `${location.sent / peak * 100}%` }} />}</span>
    </button>)}{!data.locations.length && <p className="atlas-list-empty">{loading ? 'Loading locations…' : 'No traffic observed at this time.'}</p>}</div> : <MapTrackList tracks={data.tracks} selectedId={selectedTrack} activeOnly={activeOnly} onActiveOnly={onActiveOnly} onSelect={onTrack} />}
    <div className="atlas-overview-bottom"><span>{state.expanded ? 'Filters apply to every track' : 'Drag the edge to explore'}</span><button type="button" onClick={() => onChange({ ...state, expanded: !state.expanded })}>{state.expanded ? 'Map ↙' : 'Timeline ↗'}</button></div>
    {!state.expanded && <div className="atlas-pane-resize" role="separator" aria-label="Expand overview into timeline; press Enter" aria-orientation="vertical" tabIndex={0} aria-valuemin={260} aria-valuemax={1000} aria-valuenow={dragWidth ?? 290}
      onKeyDown={event => { if (event.key === 'Enter' || event.key === 'ArrowRight') { event.preventDefault(); onChange({ ...state, expanded: true }) } }}
      onPointerDown={event => { if (event.button !== 0) return; event.preventDefault(); const box = aside.current!.getBoundingClientRect(); drag.current = { start: event.clientX, width: box.width, limit: Math.max(360, (aside.current?.parentElement?.clientWidth ?? window.innerWidth) * .58) }; event.currentTarget.setPointerCapture(event.pointerId) }}
      onPointerMove={event => { if (!drag.current) return; const width = Math.max(260, drag.current.width + event.clientX - drag.current.start); setDragWidth(Math.min(width, drag.current.limit)); setSnap(width >= drag.current.limit) }}
      onPointerUp={event => { if (!drag.current) return; const expand = drag.current.width + event.clientX - drag.current.start >= drag.current.limit; drag.current = null; setDragWidth(null); setSnap(false); event.currentTarget.releasePointerCapture(event.pointerId); if (expand) onChange({ ...state, expanded: true }) }}
      onPointerCancel={() => { drag.current = null; setDragWidth(null); setSnap(false) }} />}
    {snap && <div className="atlas-snap-target">Release to open the timeline<small>Keep direction, location, and playback position</small></div>}
  </aside>
}
