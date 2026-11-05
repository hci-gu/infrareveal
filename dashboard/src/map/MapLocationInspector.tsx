import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import type { ActivityOrder } from './activityOrder'
import { useEffect, useRef } from 'react'
import type { CSSProperties } from 'react'
import { MapIcon } from './MapIcon'
import { colorCSS } from './mapTracks'
import type { MapTrack, seriesTraffic } from './mapTracks'
import { directionLabel } from './mapWorkspace'
import type { LocationTraffic, TrafficDirection } from './mapWorkspace'
import { formatBytes } from './format'

type Props = { cursorMs: number; order?: ActivityOrder; refreshing: boolean;
  location: LocationTraffic
  tracks: MapTrack[]
  direction: TrafficDirection
  traffic: ReturnType<typeof seriesTraffic>
  loading: boolean
  error: boolean
  trafficLoading: boolean
  onTrack: (id: string) => void
  onClose: () => void
  onFit: () => void
}

export function MapLocationInspector({ cursorMs, order, refreshing, location, tracks, direction, traffic, loading, error, trafficLoading, onTrack, onClose, onFit }: Props) {
  const ref = useRef<HTMLElement>(null)
  useEffect(() => { ref.current?.focus({ preventScroll: true }) }, [])
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, onFocus: focusList, pause: pauseList } = useLiveList(tracks, JSON.stringify([location.id, direction, order]), cursorMs)
  const destinations = new Set(location.series.map(series => series.chunks[0].destination_ip)).size
  const clients = new Set(location.series.map(series => series.chunks[0].client_id)).size
  const bytes = (value: number) => loading || error ? '—' : formatBytes(value)
  const peak = Math.max(1, ...tracks.map(track => track.bytes))
  return <section ref={ref} tabIndex={-1} className="atlas-track-inspector atlas-location-inspector" aria-label={`${location.label} location details`} onKeyDown={event => {
    if (event.key === 'Escape') { event.stopPropagation(); onClose() }
  }}>
    <header className="atlas-inspector-heading"><span>SELECTED LOCATION</span><button type="button" className="atlas-icon-button" aria-label="Close location details" onClick={onClose}><MapIcon name="close" /></button></header>
    <div className="atlas-track-title"><h2>{location.label}</h2><p>{location.detail}</p><span>{destinations} {destinations === 1 ? 'destination' : 'destinations'} · {clients} {clients === 1 ? 'client' : 'clients'} · {location.series.length} series</span></div>
    <div className="atlas-track-summary">
      <div><strong>{bytes(location.bytes)}</strong><span>{directionLabel(direction)} · loaded window to playhead</span></div>
      <div><strong>{trafficLoading || !traffic.available ? '—' : `${formatBytes(traffic.rate)}/s`}</strong><span>Captured payload rate{trafficLoading ? ' · loading' : traffic.partial ? ' · partial capture' : ''}</span></div>
    </div>
    <div className="atlas-location-directions">
      {direction !== 'sent' && <div className="atlas-down"><strong data-location-total="received">↓ {bytes(location.received)}</strong><span>Downloaded</span></div>}
      {direction !== 'received' && <div className="atlas-up"><strong data-location-total="sent">↑ {bytes(location.sent)}</strong><span>Sent</span></div>}
    </div>
    <div className="atlas-track-map-status"><span role="status">{refreshing ? 'Updating · showing last loaded capture' : loading ? 'Loading totals…' : error ? 'Capture unavailable' : location.partial ? 'Captured wire bytes · partial capture' : 'Captured wire bytes'}</span><button type="button" disabled={!location.position} onClick={onFit}>Fit location</button></div>
    {location.country && <p className="atlas-location-note">Only destinations without a city estimate. The footprint does not show where within the country traffic goes.</p>}
    <BackToLatest paused={listPaused} onClick={resumeList} /><div ref={listRef} onScroll={scrollList} onFocusCapture={focusList} onClick={pauseList} className="atlas-inspector-scroll">
      <div className="atlas-section-heading"><h3>Services at this location <span className="atlas-count">{tracks.length}</span></h3></div>
      <div className="atlas-location-services">{orderedItems.map(track => <button type="button" key={track.id} className="atlas-destination atlas-track" data-location-track-id={track.id} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} aria-label={`Inspect ${track.label} · ${track.client}`} onClick={() => onTrack(track.id)}>
        <span className="atlas-track-dot" /><span className="atlas-destination-content"><span className="atlas-destination-name">{track.label}</span><span className="atlas-destination-location">{track.client} · {track.series.length} series</span><span className="atlas-volume-track" aria-hidden="true"><span style={{ width: `${track.bytes / peak * 100}%` }} /></span></span>
        <span className="atlas-destination-volume">{bytes(track.bytes)}<MapIcon name="arrow" size={13} /></span>
      </button>)}</div>
      {!tracks.length && <p className="atlas-list-empty">{loading ? 'Loading services…' : 'No traffic in this direction at the playhead.'}</p>}
    </div>
  </section>
}
