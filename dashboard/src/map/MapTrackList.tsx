import { useState } from 'react'
import type { CSSProperties } from 'react'
import { colorCSS } from './mapTracks'
import type { MapTrack } from './mapTracks'
import { formatBytes } from './format'
import { MapIcon } from './MapIcon'

type Props = { tracks: MapTrack[]; selectedId: string | null; activeOnly: boolean; onActiveOnly: (value: boolean) => void; onSelect: (id: string | null) => void }

export function MapTrackList({ tracks, selectedId, activeOnly, onActiveOnly, onSelect }: Props) {
  const [query, setQuery] = useState('')
  const search = query.trim().toLowerCase()
  const visible = tracks.filter(track => (!activeOnly || track.activeCount > 0) && (!search || [track.label, track.site, track.client].some(value => value.toLowerCase().includes(search))))
  const peak = Math.max(1, ...tracks.map(track => track.bytes))
  return <section className="atlas-destinations atlas-tracks" aria-label="Traffic tracks">
    <div className="atlas-section-heading"><h2>Traffic tracks <span className="atlas-count">{tracks.length}</span></h2><span>BY VOLUME</span></div>
    <div className="atlas-segmented" aria-label="Track filter"><button type="button" aria-pressed={!activeOnly} onClick={() => onActiveOnly(false)}>All observed</button><button type="button" aria-pressed={activeOnly} onClick={() => onActiveOnly(true)}>Active now</button></div>
    <input className="atlas-search atlas-track-search" type="search" aria-label="Find traffic tracks" placeholder="Find a site or client…" value={query} onChange={event => setQuery(event.target.value)} />
    <div className="atlas-destination-list atlas-track-list">
      {visible.map(track => <button type="button" className={`atlas-destination atlas-track ${selectedId === track.id ? 'is-selected' : ''} ${selectedId && selectedId !== track.id ? 'is-dimmed' : ''}`} key={track.id} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} aria-label={`${track.label} · ${track.client} · ${track.connections.length} connections`} aria-pressed={selectedId === track.id} data-track-id={track.id} onClick={() => onSelect(selectedId === track.id ? null : track.id)}>
        <span className="atlas-track-dot" />
        <span className="atlas-destination-content"><span className="atlas-destination-name">{track.label}</span><span className="atlas-destination-location">{track.connections.length} connections · {track.client}</span><span className="atlas-volume-track"><span style={{ width: `${track.bytes / peak * 100}%` }} /></span></span>
        <span className="atlas-destination-volume">{formatBytes(track.bytes)}<MapIcon name="arrow" size={13} /></span>
      </button>)}
      {visible.length === 0 && <p className="atlas-list-empty">{search ? 'No matching tracks.' : activeOnly ? 'No active tracks at this moment.' : 'Tracks appear as connections are observed.'}</p>}
    </div>
  </section>
}
