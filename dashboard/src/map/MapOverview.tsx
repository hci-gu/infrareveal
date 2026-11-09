import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import { memo, useState } from 'react'
import { formatBytes, formatMinute } from './format'
import { MapIcon } from './MapIcon'
import { MapTrackList } from './MapTrackList'
import { DEFAULT_TRAFFIC_FILTERS, filterScope } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'

export const MapOverview = memo(function MapOverview({ data, state, onChange, startMs, cursorMs, capturedToMs, loading, error, refreshing, selectedTrack, onTrack, selectedLocation, onLocation }: {
  data: WorkspaceProjection; state: WorkspaceState; onChange: (value: WorkspaceState) => void; startMs: number; cursorMs: number; capturedToMs: number; loading: boolean; error: boolean; refreshing: boolean
  selectedTrack: string | null; onTrack: (id: string | null) => void; selectedLocation: string | null; onLocation: (id: string | null) => void
}) {
  const [tab, setTab] = useState<'locations' | 'tracks'>('locations')
  const peak = Math.max(1, ...data.locations.map(location => location.bytes))
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, onFocus: focusList, pause: pauseList } = useLiveList(data.locations, JSON.stringify([data.scene.sessionId, filterScope(state), state.order, tab]), cursorMs, state.order === 'latest' ? location => location.lastActivityMs : undefined)
  return <aside className="atlas-overview" aria-label="Traffic overview">
    <div className="atlas-overview-heading"><h1>Traffic overview</h1><button type="button" className="atlas-icon-button" aria-label={state.expanded ? 'Back to map' : 'Expand traffic timeline'} onClick={() => onChange({ ...state, expanded: !state.expanded })}><MapIcon name={state.expanded ? 'back' : 'expand'} size={17} /></button></div>
    <p className="atlas-scope">{formatMinute(Math.max(startMs, cursorMs - (state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs)))} - {formatMinute(Math.min(cursorMs, capturedToMs))}</p>
    <div className="atlas-metrics atlas-direction-metrics">
      <div className="atlas-down"><span className="atlas-metric-label">↓ Downloaded</span><strong data-direction-total="received">{loading || error ? '—' : formatBytes(data.total.received)}</strong></div>
      <div className="atlas-up"><span className="atlas-metric-label">↑ Sent</span><strong data-direction-total="sent">{loading || error ? '—' : formatBytes(data.total.sent)}</strong></div>
    </div>
    <div className="atlas-segmented atlas-overview-tabs" role="group" aria-label="Overview content"><button type="button" aria-pressed={tab === 'locations'} onClick={() => setTab('locations')}>Locations <small>{data.locations.length}</small></button><button type="button" aria-pressed={tab === 'tracks'} onClick={() => setTab('tracks')}>Tracks <small>{data.tracks.length}</small></button></div>
    {tab === 'locations' && <BackToLatest paused={listPaused} onClick={resumeList} />}
    {tab === 'locations' ? <div ref={listRef} onScroll={scrollList} onFocusCapture={focusList} onClick={pauseList} className="atlas-location-list" aria-label="Remote locations">{orderedItems.map(location => <button type="button" key={location.id} className="atlas-location-row" aria-pressed={selectedLocation === location.id} data-location-id={location.id} onClick={() => onLocation(selectedLocation === location.id ? null : location.id)}>
      <span>{location.label}</span><strong>{loading || error ? '—' : formatBytes(location.bytes)}</strong><small>{location.detail}</small>
      <span className="atlas-location-bars" aria-hidden="true"><i className="atlas-down-bar" style={{ width: `${location.received / peak * 100}%` }} /><i className="atlas-up-bar" style={{ width: `${location.sent / peak * 100}%` }} /></span>
    </button>)}{!data.locations.length && <p className="atlas-list-empty">{loading ? 'Loading locations…' : error ? 'Locations unavailable · retrying' : refreshing ? 'Updating locations…' : 'No traffic observed at this time.'}</p>}</div> : <MapTrackList loading={loading} error={error} refreshing={refreshing} cursorMs={cursorMs} scope={JSON.stringify([data.scene.sessionId, filterScope(state), state.order])} order={state.order} tracks={data.tracks} selectedId={selectedTrack} onSelect={onTrack} />}
  </aside>
})
