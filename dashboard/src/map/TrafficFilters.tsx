import { useCallback, useEffect, useRef } from 'react'
import { DEFAULT_TRAFFIC_FILTERS, trafficFilterCount } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import { MapIcon } from './MapIcon'
import { clientVisibilityRows, toggleClient } from './clientVisibility'
import type { ConnectedClientsState } from './useConnectedClients'

export function TrafficFilters({ open, state, data, clients, onChange, onClose }: {
  open: boolean; state: WorkspaceState; data: WorkspaceProjection; clients: ConnectedClientsState | null; onChange: (value: WorkspaceState) => void; onClose: () => void
}) {
  const clientRows = clientVisibilityRows(clients, state)
  const search = useRef<HTMLInputElement>(null)
  const close = useCallback(() => { onClose(); document.getElementById('traffic-filters-toggle')?.focus({ preventScroll: true }) }, [onClose])
  useEffect(() => { if (open) search.current?.focus({ preventScroll: true }) }, [open])
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape') return
      event.preventDefault(); event.stopPropagation(); close()
    }
    document.addEventListener('keydown', onKey, true)
    return () => document.removeEventListener('keydown', onKey, true)
  }, [open, close])
  return <aside id="traffic-filters" className="atlas-filter-drawer" aria-labelledby="traffic-filters-title" aria-hidden={!open} inert={!open} data-open={open || undefined}>
    <header><div><h2 id="traffic-filters-title">Filters</h2><p>Applies to the map, lists and timeline.</p></div><button type="button" className="atlas-icon-button" aria-label="Close filters" onClick={close}><MapIcon name="close" /></button></header>
    <div className="atlas-filter-fields">
      <label htmlFor="traffic-filter-search">Search</label>
      <input ref={search} id="traffic-filter-search" type="search" placeholder="Service, client, IP or location…" value={state.query ?? ''} onChange={event => onChange({ ...state, query: event.target.value })} />
      <label htmlFor="traffic-filter-window">History</label>
      <select id="traffic-filter-window" value={state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs} onChange={event => onChange({ ...state, windowMs: Number(event.target.value) })}>
        <option value={30_000}>30 seconds</option><option value={60_000}>1 minute</option><option value={300_000}>5 minutes</option><option value={1_800_000}>30 minutes</option>
      </select>
      <p>How far back graphs and totals go.</p>
      <div className="atlas-filter-switch"><div><span id="traffic-filter-active-label">Only active now</span><p id="traffic-filter-active-help">Traffic within the last 15 seconds of the playhead.</p></div><button type="button" className="atlas-switch" role="switch" aria-labelledby="traffic-filter-active-label" aria-describedby="traffic-filter-active-help" aria-checked={state.activeOnly ?? false} onClick={() => onChange({ ...state, activeOnly: !state.activeOnly })}><span /></button></div>
      <label htmlFor="traffic-filter-location">Location</label>
      <select id="traffic-filter-location" value={state.locationId ?? ''} onChange={event => onChange({ ...state, locationId: event.target.value || null })}>
        <option value="">All locations</option>
        {state.locationId && !data.locationOptions.some(location => location.id === state.locationId) && <option value={state.locationId}>Location outside loaded history</option>}
        {data.locationOptions.map(location => <option key={location.id} value={location.id}>{location.label}</option>)}
      </select>
      {clientRows.length > 0 && <div className="atlas-filter-clients" role="group" aria-labelledby="traffic-filter-clients-label">
        <div className="atlas-filter-clients-heading"><span id="traffic-filter-clients-label">Clients{clients && <small>{clients.connected} connected</small>}</span>{(state.hiddenClients?.length ?? 0) > 0 && <button type="button" onClick={() => onChange({ ...state, hiddenClients: [] })}>Show all</button>}</div>
        {clientRows.map(row => <div key={row.key} className="atlas-filter-switch" data-connected={row.connected}>
          <div><span id={`traffic-filter-client-${row.key}`}>{row.label}</span><p>{row.detail}</p></div>
          <button type="button" className="atlas-switch" role="switch" aria-labelledby={`traffic-filter-client-${row.key}`} aria-checked={!row.hidden} onClick={() => onChange(toggleClient(state, row))}><span /></button>
        </div>)}
      </div>}
    </div>
    <footer><p>{data.bySeries.size} {data.bySeries.size === 1 ? 'endpoint' : 'endpoints'} · {data.tracks.length} {data.tracks.length === 1 ? 'track' : 'tracks'}</p><button type="button" disabled={trafficFilterCount(state) === 0} onClick={() => onChange({ ...state, ...DEFAULT_TRAFFIC_FILTERS })}>Reset filters</button></footer>
  </aside>
}
