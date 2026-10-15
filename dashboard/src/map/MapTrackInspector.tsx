import { measureRoute, routeForSeriesAt } from '@infrareveal/session-state'
import { useState } from 'react'
import type { CSSProperties } from 'react'
import { colorCSS } from './mapTracks'
import type { MapSeries, MapTrack, MapTrackCatalog, trackTraffic } from './mapTracks'
import { formatBytes, formatCursor } from './format'
import { MapIcon } from './MapIcon'
import { directionLabel } from './mapWorkspace'
import type { TrafficDirection } from './mapWorkspace'
import { MapRouteDetails } from './MapRouteDetails'

type Props = { direction: TrafficDirection; track: MapTrack; catalog: MapTrackCatalog; cursorMs: number; traffic: ReturnType<typeof trackTraffic>; onClose: () => void; onFit: () => void }
export function MapTrackInspector({ direction, track, catalog, cursorMs, traffic, onClose, onFit }: Props) {
  const [query, setQuery] = useState('')
  const search = query.trim().toLowerCase()
  const series = track.series.filter(value => [value.hostname, value.chunks[0].destination_ip, value.location].some(text => text.toLowerCase().includes(search)))
  return <section tabIndex={-1} className="atlas-track-inspector" aria-label={`${track.label} details`} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} onKeyDown={event => { if (event.key === 'Escape') onClose() }}>
    <header className="atlas-inspector-heading"><span>SELECTED SERVICE</span><button className="atlas-icon-button" aria-label="Close service details" onClick={onClose}><MapIcon name="close" /></button></header>
    <div className="atlas-track-title"><h2>{track.label}</h2><span>Client <b>{track.client}</b></span><p>Inferred service activity; it does not establish which page a person viewed.</p></div>
    <div className="atlas-track-summary"><div><strong>{formatBytes(track.bytes)}</strong><span>{directionLabel(direction)} · loaded window to playhead</span></div><div><strong>{traffic.available ? `${formatBytes(traffic.rate)}/s` : '—'}</strong><span>Captured payload rate{traffic.partial ? ' · partial capture' : ''}</span></div></div>
    <div className="atlas-track-map-status"><span>{track.mappedCount} of {track.series.length} traffic series mapped</span><button disabled={!track.mappedCount} onClick={onFit}>Fit service</button></div>
    <div className="atlas-inspector-scroll"><input className="atlas-search" type="search" aria-label="Find service destinations" placeholder="Find hostname, IP, or place…" value={query} onChange={event => setQuery(event.target.value)} />
      {series.map(value => <SeriesDetails key={value.id} series={value} catalog={catalog} cursorMs={cursorMs} />)}
    </div>
  </section>
}
function SeriesDetails({ series, catalog, cursorMs }: { series: MapSeries; catalog: MapTrackCatalog; cursorMs: number }) {
  const chunk = series.chunks[series.chunks.length - 1]
  const route = routeForSeriesAt(chunk, catalog.window.routes, cursorMs)
  const [message, setMessage] = useState('')
  return <details className="atlas-connection"><summary><span className="atlas-connection-name"><strong>{series.hostname}</strong><small>{chunk.destination_ip}:{chunk.destination_port} · {chunk.protocol.toUpperCase()}</small></span><span>{formatBytes(series.bytes)}</span></summary>
    <div className="atlas-connection-body"><dl><div><dt>Location</dt><dd>{series.location || 'Unknown'}</dd></div><div><dt>Provider</dt><dd>{series.provider || 'Unknown'}</dd></div><div><dt>Classification</dt><dd>{chunk.evidence.source || 'Independent endpoint'} · {chunk.evidence.confidence || 'unknown'}{chunk.evidence.ambiguous ? ' · ambiguous' : ''}</dd></div><div><dt>Observed</dt><dd>{formatCursor(chunk.evidence.observed_ms)} UTC · {chunk.sealed ? 'sealed' : 'provisional'}</dd></div></dl>
      {route ? <MapRouteDetails route={route} cursorMs={cursorMs} /> : <p>Intermediate route unknown at this time. The direct line is an endpoint approximation.</p>}
      {catalog.manifest?.active && <button onClick={async () => { try { await measureRoute(chunk.id); setMessage('Measurement requested.') } catch (error) { setMessage(error instanceof Error ? error.message : 'Measurement unavailable') } }}>Measure destination</button>}<p role="status">{message}</p>
    </div>
  </details>
}
