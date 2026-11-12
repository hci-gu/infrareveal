import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import type { ActivityOrder } from './activityOrder'
import { useEffect, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { colorCSS } from './mapTracks'
import type { MapSeries, MapTrack, trackTraffic } from './mapTracks'
import { formatBytes, formatCursor } from './format'
import { MapIcon } from './MapIcon'

type Props = { cursorMs: number; order?: ActivityOrder; refreshing: boolean; track: MapTrack; traffic: ReturnType<typeof trackTraffic>; locationLabel?: string; onClose: () => void; onFit: () => void }
export function MapTrackInspector({ cursorMs, order, refreshing, track, traffic, locationLabel, onClose, onFit }: Props) {
  const ref = useRef<HTMLElement>(null)
  useEffect(() => { ref.current?.focus({ preventScroll: true }) }, [])
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, onFocus: focusList, pause: pauseList } = useLiveList(track.series, JSON.stringify([track.id, order]), cursorMs)
  const scope = JSON.stringify([track.id, order])
  const [page, setPage] = useState({ scope, offset: 0 })
  const offset = Math.min(page.scope === scope ? page.offset : 0, Math.max(0, Math.floor((orderedItems.length - 1) / 20) * 20))
  return <section ref={ref} tabIndex={-1} className="atlas-track-inspector" aria-label={`${track.label} details`} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); onClose() } }}>
    <header className="atlas-inspector-heading"><span>SELECTED SERVICE</span><button className="atlas-icon-button" aria-label="Close service details" onClick={onClose}><MapIcon name="close" /></button></header>
    {locationLabel && <button type="button" className="atlas-inspector-back" onClick={onClose}><MapIcon name="back" size={13} />Back to {locationLabel}</button>}
    <div className="atlas-track-title"><h2>{track.label}</h2><span>Client <b>{track.client}</b></span><p>Inferred service activity; it does not establish which page a person viewed.</p></div>
    <div className="atlas-track-summary"><div><strong>{formatBytes(track.bytes)}</strong><span>Downloaded + sent · loaded window to playhead</span></div><div><strong>{traffic.available ? `${formatBytes(traffic.rate)}/s` : '—'}</strong><span>Captured payload rate{traffic.partial ? ' · partial capture' : ''}</span></div></div>
    <div className="atlas-track-map-status"><span>{refreshing ? 'Updating · ' : ''}{track.mappedCount} of {track.series.length} traffic series mapped</span><button disabled={!track.mappedCount} onClick={onFit}>Fit service</button></div>
    <BackToLatest paused={listPaused} onClick={resumeList} /><div ref={listRef} onScroll={scrollList} onFocusCapture={focusList} onClick={pauseList} className="atlas-inspector-scroll">
      {orderedItems.length > 20 && <nav className="atlas-series-pages" aria-label="Traffic series pages"><button disabled={offset === 0} onClick={() => setPage({ scope, offset: offset - 20 })}>Previous</button><span>{offset + 1}–{Math.min(offset + 20, orderedItems.length)} of {orderedItems.length}</span><button disabled={offset + 20 >= orderedItems.length} onClick={() => setPage({ scope, offset: offset + 20 })}>Next</button></nav>}
      {orderedItems.slice(offset, offset + 20).map(value => <SeriesDetails key={value.id} series={value} />)}
    </div>
  </section>
}
function SeriesDetails({ series }: { series: MapSeries }) {
  const chunk = series.chunks[series.chunks.length - 1]
  return <details className="atlas-connection"><summary><span className="atlas-connection-name"><strong>{series.hostname}</strong><small>{chunk.destination_ip}:{chunk.destination_port} · {chunk.protocol.toUpperCase()}</small></span><span>{formatBytes(series.bytes)}</span></summary>
    <div className="atlas-connection-body"><dl><div><dt>Location</dt><dd>{series.location || 'Unknown'}</dd></div><div><dt>Provider</dt><dd>{series.provider || 'Unknown'}</dd></div><div><dt>Classification</dt><dd>{chunk.evidence.source || 'Independent endpoint'} · {chunk.evidence.confidence || 'unknown'}{chunk.evidence.ambiguous ? ' · ambiguous' : ''}</dd></div><div><dt>Observed</dt><dd>{formatCursor(chunk.evidence.observed_ms)} UTC · {chunk.sealed ? 'sealed' : 'provisional'}</dd></div></dl>
    </div>
  </details>
}
