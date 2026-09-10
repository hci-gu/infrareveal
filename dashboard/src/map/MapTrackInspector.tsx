import { routeForFlowAt } from '@infrareveal/session-state'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { parseEpoch } from '@infrareveal/session-state'
import { colorCSS } from './mapTracks'
import type { MapConnection, MapTrack, MapTrackCatalog, trackTraffic } from './mapTracks'
import { formatBytes, formatCursor, formatElapsed } from './format'
import { MapIcon } from './MapIcon'
import { MapRouteDetails } from './MapRouteDetails'

type Props = { track: MapTrack; catalog: MapTrackCatalog; cursorMs: number; traffic: ReturnType<typeof trackTraffic>; onClose: () => void; onFit: () => void }
const PAGE_SIZE = 40

export function MapTrackInspector({ track, catalog, cursorMs, traffic, onClose, onFit }: Props) {
  const [tab, setTab] = useState<'connections' | 'evidence'>('connections')
  const [query, setQuery] = useState('')
  const [page, setPage] = useState(0)
  const panel = useRef<HTMLElement>(null)
  useEffect(() => { panel.current?.focus({ preventScroll: true }) }, [])
  const connections = useMemo(() => {
    const search = query.trim().toLowerCase()
    return track.connections.filter(connection => !search || [connection.hostname, connection.flow.destination_ip, connection.flow.protocol, String(connection.flow.destination_port), connection.location].some(value => value.toLowerCase().includes(search))).sort((a, b) => b.bytes - a.bytes || a.flow.id.localeCompare(b.flow.id))
  }, [query, track.connections])
  const currentPage = Math.min(page, Math.max(0, Math.ceil(connections.length / PAGE_SIZE) - 1))
  const evidence = useMemo(() => {
    const flowIds = new Set(track.connections.map(connection => connection.flow.id))
    const attributions = catalog.data.attributions.filter(record => flowIds.has(record.flow) && parseEpoch(record.observed_at, Infinity) <= cursorMs)
    const dnsIds = new Set(attributions.map(record => record.dns_query))
    return {
      attributions,
      associations: catalog.data.flowAssociations.filter(record => flowIds.has(record.flow) && parseEpoch(record.observed_at, Infinity) <= cursorMs),
      dns: catalog.data.dnsQueries.filter(record => record.client_ip === track.client && dnsIds.has(record.id) && parseEpoch(record.timestamp, Infinity) <= cursorMs),
    }
  }, [catalog, cursorMs, track.client, track.connections])
  const evidenceCount = evidence.attributions.length + evidence.associations.length + evidence.dns.length
  return <section ref={panel} tabIndex={-1} className="atlas-track-inspector" aria-label={`${track.label} track details`} style={{ '--track-color': colorCSS(track.color) } as CSSProperties} onKeyDown={event => { if (event.key === 'Escape') { event.stopPropagation(); onClose() } }}>
    <header className="atlas-inspector-heading"><span><i className="atlas-track-dot" />SELECTED TRACK</span><button className="atlas-icon-button" type="button" aria-label="Close track details" onClick={onClose}><MapIcon name="close" size={17} /></button></header>
    <div className="atlas-track-title"><h2>{track.label}</h2>{track.site !== track.label && <p>{track.site || 'Connections without a supported activity association'}</p>}<span>Client <b>{track.client}</b></span></div>
    <div className="atlas-track-summary"><div><strong>{track.connections.length}</strong><span>Connections <b>· {track.activeCount} active</b></span></div><div><strong>{formatBytes(track.bytes)}</strong><span>Observed volume</span></div><div><strong>{traffic.available ? `${formatBytes(traffic.rate)}/s` : '—'}</strong><span>{traffic.estimated ? 'Estimated average' : 'Recent payload rate'}{traffic.partial ? ' · Partial' : ''}</span></div><div><strong>{new Set(track.connections.map(connection => connection.flow.destination_ip)).size}</strong><span>Destinations</span></div></div>
    <div className="atlas-track-map-status"><span>{track.mappedCount} of {track.connections.length} connections mapped</span><button type="button" disabled={!track.mappedCount} onClick={onFit}><MapIcon name="expand" size={12} />Fit track</button></div>
    <div className="atlas-inspector-tabs" role="group" aria-label="Track detail view"><button type="button" aria-pressed={tab === 'connections'} onClick={() => setTab('connections')}>Connections <span>{track.connections.length}</span></button><button type="button" aria-pressed={tab === 'evidence'} onClick={() => setTab('evidence')}>Observations <span>{evidenceCount}</span></button></div>
    <div className="atlas-inspector-scroll">
      {tab === 'connections' ? <>
        <input className="atlas-search" type="search" aria-label="Find connections in track" placeholder="Find hostname, IP, or protocol…" value={query} onChange={event => { setQuery(event.target.value); setPage(0) }} />
        <div className="atlas-track-connections">{connections.slice(currentPage * PAGE_SIZE, (currentPage + 1) * PAGE_SIZE).map(connection => <Connection key={connection.flow.id} connection={connection} cursorMs={cursorMs} catalog={catalog} />)}</div>
        {connections.length === 0 && <p className="atlas-list-empty">No matching connections.</p>}
        {connections.length > PAGE_SIZE && <div className="atlas-track-pagination"><button type="button" disabled={currentPage === 0} onClick={() => setPage(currentPage - 1)}>Previous</button><span>{currentPage * PAGE_SIZE + 1}–{Math.min(connections.length, (currentPage + 1) * PAGE_SIZE)} of {connections.length}</span><button type="button" disabled={(currentPage + 1) * PAGE_SIZE >= connections.length} onClick={() => setPage(currentPage + 1)}>Next</button></div>}
      </> : <div className="atlas-track-evidence">
        {track.episode && <section><h3>Activity group</h3><p>{track.episode.explanation}</p><small>{track.episode.confidence} confidence · {track.episode.anchor_hostname}</small></section>}
        <section><h3>Activity associations <span>{evidence.associations.length}</span></h3>{evidence.associations.map(record => <details key={record.id}><summary>{record.parent_label}<small>{record.relationship.replace(/_/g, ' ')} · {record.confidence}</small></summary><p>{record.explanation}</p><small>Connection {record.flow} · {formatCursor(parseEpoch(record.observed_at, 0))} UTC</small></details>)}{!evidence.associations.length && <p>No supported parent activity has been identified.</p>}</section>
        <section><h3>Hostname observations <span>{evidence.attributions.length}</span></h3>{evidence.attributions.map(record => <details key={record.id}><summary>{record.confidence === 'hidden' ? 'Hostname withheld' : record.candidate_hostname}<small>{record.source_signal} · {record.confidence}</small></summary><p>{record.explanation}</p><small>Connection {record.flow} · {formatCursor(parseEpoch(record.observed_at, 0))} UTC</small></details>)}</section>
        <section><h3>Linked DNS queries <span>{evidence.dns.length}</span></h3>{evidence.dns.map(record => <details key={record.id}><summary>{record.query_name}<small>{record.query_type} · {formatCursor(parseEpoch(record.timestamp, 0))} UTC</small></summary><p>{record.answers?.join(', ') || 'No answers'}</p>{Boolean(record.aliases?.length) && <p>Aliases: {record.aliases!.join(' → ')}</p>}</details>)}<p>DNS queries are shown for the loaded activity window.</p></section>
      </div>}
    </div>
  </section>
}

function Connection({ connection, cursorMs, catalog }: { connection: MapConnection; cursorMs: number; catalog: MapTrackCatalog }) {
  const { flow } = connection
  const selectedRoute = routeForFlowAt(flow, catalog.data.routes, cursorMs)
  const routes = selectedRoute ? [selectedRoute] : []
  return <details className="atlas-connection" data-flow-id={flow.id}>
    <summary><span className={`atlas-connection-status ${connection.active ? 'is-active' : ''}`} /><span className="atlas-connection-name"><strong>{connection.hostname}</strong><small>{flow.destination_ip}:{flow.destination_port} · {flow.protocol.toUpperCase()}</small></span><span className="atlas-connection-bytes">{formatBytes(connection.bytes)}<small>{connection.mapped ? connection.location || 'Located' : 'Unmapped'}</small></span></summary>
    <div className="atlas-connection-body"><dl>
      <div><dt>Client socket</dt><dd>{flow.client_ip}:{flow.source_port}</dd></div><div><dt>Connection</dt><dd>{flow.id}</dd></div><div><dt>Last reported state</dt><dd>{flow.state}</dd></div>
      <div><dt>Received / sent</dt><dd>{formatBytes(flow.bytes_in)} / {formatBytes(flow.bytes_out)}</dd></div><div><dt>Packets received / sent</dt><dd>{flow.packets_in.toLocaleString()} / {flow.packets_out.toLocaleString()}</dd></div>
      <div><dt>First observed</dt><dd>{formatCursor(connection.startMs)} UTC</dd></div><div><dt>Observed duration</dt><dd>{formatElapsed((Math.min(cursorMs, connection.endMs) - connection.startMs) / 1000)}</dd></div>
      {connection.provider && <div><dt>Network provider</dt><dd>{connection.provider}</dd></div>}
      {connection.association && <div><dt>Activity association</dt><dd>{connection.association.relationship.replace(/_/g, ' ')} · {connection.association.confidence}</dd></div>}
      {connection.attribution && <div><dt>Hostname confidence</dt><dd>{connection.attribution.confidence}</dd></div>}
    </dl>
    {routes.map(route => <MapRouteDetails key={route.id} route={route} cursorMs={cursorMs} />)}
    {!routes.length && <p className="atlas-route-explanation">No traceroute available at this time.{connection.mapped ? ' The map shows an approximate connection to the destination.' : ' This destination has no map location.'}</p>}
    </div>
  </details>
}
