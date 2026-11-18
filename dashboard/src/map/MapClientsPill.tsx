import { memo, useEffect, useRef, useState } from 'react'
import type { WorkspaceState } from './mapWorkspace'
import type { ConnectedClientsState } from './useConnectedClients'
import { clientVisibilityRows, toggleClient } from './clientVisibility'

/** Live Wi-Fi association count; unfolds into per-client map visibility toggles. */
export const MapClientsPill = memo(function MapClientsPill({ clients, workspace, onWorkspace }: {
  clients: ConnectedClientsState | null; workspace: WorkspaceState; onWorkspace: (value: WorkspaceState) => void
}) {
  const [open, setOpen] = useState(false)
  const rootRef = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape') { event.preventDefault(); setOpen(false) } }
    const onPointer = (event: PointerEvent) => { if (!rootRef.current?.contains(event.target as Node)) setOpen(false) }
    window.addEventListener('keydown', onKey)
    window.addEventListener('pointerdown', onPointer)
    return () => { window.removeEventListener('keydown', onKey); window.removeEventListener('pointerdown', onPointer) }
  }, [open])
  if (!clients) return null
  const hidden = workspace.hiddenClients ?? []
  const rows = clientVisibilityRows(clients, workspace)
  const visibleCount = rows.filter(row => row.connected && !row.hidden).length
  return <div ref={rootRef} className="atlas-clients" data-open={open || undefined}>
    <button type="button" className="atlas-clients-pill" aria-expanded={open} aria-controls="atlas-clients-list" onClick={() => setOpen(value => !value)} title="Devices joined to the InfraReveal Wi-Fi (display screens excluded)">
      <span className="atlas-connected-dot" aria-hidden="true" />
      <strong>{clients.connected}</strong>
      <span>{clients.connected === 1 ? 'client' : 'clients'} connected</span>
      {hidden.length > 0 && <small>{hidden.length} hidden</small>}
      <svg className="atlas-clients-chevron" width="10" height="10" viewBox="0 0 10 10" aria-hidden="true"><path d="M2 3.5 5 6.5 8 3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" /></svg>
    </button>
    {open && <div id="atlas-clients-list" className="atlas-clients-panel" role="group" aria-label="Client visibility">
      <div className="atlas-clients-panel-heading"><span>Show on map</span>{hidden.length > 0 && <button type="button" onClick={() => onWorkspace({ ...workspace, hiddenClients: [] })}>Show all</button>}</div>
      {rows.length ? <ul>{rows.map(row => <li key={row.key}><label className="atlas-client-row" data-connected={row.connected}>
        <input type="checkbox" checked={!row.hidden} onChange={() => onWorkspace(toggleClient(workspace, row))} />
        <span className="atlas-client-switch" aria-hidden="true" />
        <span className="atlas-client-text"><span>{row.label}</span><small>{row.detail}</small></span>
      </label></li>)}</ul> : <p className="atlas-clients-empty">No devices are connected.</p>}
      <p className="atlas-clients-note">{visibleCount} of {clients.connected} shown · hiding a client removes its traffic from the map, lists and totals.</p>
    </div>}
  </div>
})
