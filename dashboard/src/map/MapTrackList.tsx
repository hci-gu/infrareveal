import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import type { ActivityOrder } from './activityOrder'
import type { CSSProperties } from 'react'
import { colorCSS } from './mapTracks'
import type { MapTrack } from './mapTracks'
import { formatBytes } from './format'
import { MapIcon } from './MapIcon'

type Props = { loading: boolean; error: boolean; refreshing: boolean; cursorMs: number; scope: string; order?: ActivityOrder; tracks: MapTrack[]; selectedId: string | null; onSelect: (id: string | null) => void }

export function MapTrackList({ loading, error, refreshing, cursorMs, scope, order, tracks, selectedId, onSelect }: Props) {
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, onFocus: focusList, pause: pauseList } = useLiveList(tracks, scope, cursorMs, order === 'latest' ? track => track.lastActivityMs : undefined)
  const peak = Math.max(1, ...tracks.map(track => track.bytes))
  return <section className="atlas-destinations atlas-tracks" aria-label="Traffic tracks">
    <BackToLatest paused={listPaused} onClick={resumeList} />
    <div ref={listRef} onScroll={scrollList} onFocusCapture={focusList} onClick={pauseList} className="atlas-destination-list atlas-track-list">
      {orderedItems.map(track => <button type="button" className={`atlas-destination atlas-track ${selectedId === track.id ? 'is-selected' : ''} ${selectedId && selectedId !== track.id ? 'is-dimmed' : ''}`} key={track.id} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} aria-label={`${track.label} · ${track.client} · ${track.series.length} series`} aria-pressed={selectedId === track.id} data-track-id={track.id} onClick={() => onSelect(selectedId === track.id ? null : track.id)}>
        <span className="atlas-track-dot" />
        <span className="atlas-destination-content"><span className="atlas-destination-name">{track.label}</span><span className="atlas-destination-location">{track.series.length} series · {track.client}</span><span className="atlas-volume-track"><span style={{ width: `${track.bytes / peak * 100}%` }} /></span></span>
        <span className="atlas-destination-volume">{formatBytes(track.bytes)}<MapIcon name="arrow" size={13} /></span>
      </button>)}
      {tracks.length === 0 && <p className="atlas-list-empty">{loading ? 'Loading tracks…' : error ? 'Tracks unavailable · retrying' : refreshing ? 'Updating tracks…' : 'No tracks match the current filters.'}</p>}
    </div>
  </section>
}
