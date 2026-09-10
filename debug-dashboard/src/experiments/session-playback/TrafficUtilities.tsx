import { useEffect, useRef, useState } from 'react'
import { getRouteDiscoveryStatus } from '@infrareveal/session-state'
import type { RouteDiscoveryStatus, Session } from '@infrareveal/session-state'
import { Link } from 'react-router-dom'
import { X } from 'lucide-react'
import type { SessionComposition } from '../../model/sessionModel'
import { selectSceneWindow } from '../../timeline/selectors/selectSceneWindow'
import { createRecordedRenderBundle } from '../../remotion/renderBundle'
import { clearObservationData } from '../../data/clearObservationData'
import type { TimeRange } from './trafficTime'

export function TrafficUtilities({ open, onClose, view, onView, onReset, composition, range, selectedId, session, clearActivity, refresh, onCleared }: {
  open: boolean; onClose: () => void; view: 'timeline' | 'treemap'; onView: (view: 'timeline' | 'treemap') => void; onReset: () => void; composition: SessionComposition; range: TimeRange; selectedId: string | null; session: Session; clearActivity: () => void; refresh: () => Promise<void>; onCleared: () => void
}) {
  const dialog = useRef<HTMLDialogElement>(null)
  const [busy, setBusy] = useState(false)
  const [message, setMessage] = useState('')
  const [routeStatus, setRouteStatus] = useState<RouteDiscoveryStatus | null>(null)
  useEffect(() => {
    if (!open || !session.active) return
    const controller = new AbortController()
    let busy = false
    const update = async () => { if (busy) return; busy = true; try { const status = await getRouteDiscoveryStatus(controller.signal); if (!controller.signal.aborted) setRouteStatus(status) } catch { /* Older gateways have no route diagnostics. */ } finally {busy = false} }
    void update(); const timer = window.setInterval(update, 2000)
    return () => {controller.abort();window.clearInterval(timer)}
  }, [open, session.active])
  const unmatched = composition.captureStatus?.unmatched_events ?? 0
  useEffect(() => { if (open) dialog.current?.showModal(); else dialog.current?.close() }, [open])
  const exportBundle = () => {
    const sceneWindow = selectSceneWindow(composition, { ...range, overview: view === 'treemap', focusedServiceId: null, selectedClipId: selectedId })
    const blob = new Blob([JSON.stringify(createRecordedRenderBundle(session.id, sceneWindow))], { type: 'application/json' })
    const url = URL.createObjectURL(blob), anchor = document.createElement('a')
    anchor.href = url; anchor.download = `infrareveal-${session.id}-render-bundle.json`; anchor.click(); URL.revokeObjectURL(url)
  }
  return <dialog className="traffic-utilities desktop-ui" ref={dialog} onCancel={onClose} onClose={onClose} aria-label="Traffic utilities and settings"><header><h2>Traffic utilities</h2><button type="button" aria-label="Close utilities" onClick={onClose}><X size={16} /></button></header>
    <section><h3>Workspace</h3><label>View<select value={view} onChange={event => { onView(event.target.value as 'timeline' | 'treemap'); onClose() }}><option value="timeline">Timeline</option><option value="treemap">Treemap</option></select></label><button type="button" onClick={() => { onReset(); onClose() }}>Restore default layout</button><Link to="/controlled-client">Open controlled network client ↗</Link></section>
    {unmatched > 0 ? <section><h3>Unmatched observations</h3><p>{unmatched.toLocaleString()} packet observations could not be linked to a saved connection before the matching timeout. This collector total is separate from capture loss and does not mark other connections incomplete.</p><p>The count is cumulative since the collector started, as of this session's last status report.</p></section> : null}
    {routeStatus && session.active ? <section><h3>Route discovery</h3><p>{routeStatus.running} probing ({routeStatus.coverage_running ?? 0} coverage passes) · {routeStatus.pending} waiting · {routeStatus.cache_hits} cache hits</p><p>{Math.round(routeStatus.measured_byte_coverage * 100)}% of recent bytes have route evidence. Oldest wait: {(routeStatus.oldest_wait_ms / 1000).toFixed(1)}s.</p><p>{Math.round((routeStatus.reached_byte_coverage ?? 0) * 100)}% of recent bytes reach a measured destination · {Math.round((routeStatus.located_byte_coverage ?? 0) * 100)}% have a located hop. Weighted hop coverage: {Math.round((routeStatus.hop_coverage ?? 0) * 100)}%.</p><p>{routeStatus.starts} attempts · {routeStatus.failures} unsuccessful · {routeStatus.deferred} deferred</p>{routeStatus.last_error ? <p>{routeStatus.last_error}</p> : null}<p>Collector totals. Hop coverage and destination reachability can remain partial.</p></section> : null}
    <section><h3>Keyboard</h3><p>Space plays/pauses. ← / → steps one second; Shift + arrows steps five seconds. The session scrubber also supports native arrow keys. Focus a pane divider and use arrows to resize it. Escape leaves the expanded workspace.</p></section>
    <section><h3>Recorded export</h3><p>Save the current loaded scene and source times as a deterministic Remotion render bundle. Missing activity stays explicit in the bundle.</p><button type="button" disabled={session.active} onClick={exportBundle}>{session.active ? 'Available for recorded sessions' : 'Download render bundle'}</button></section>
    <section className="danger-zone"><h3>Gateway data</h3><p>Delete all observation and derived activity records. The existing confirmation applies to all sessions.</p><button type="button" disabled={busy} onClick={async () => {
      if (!window.confirm('Delete all observation and derived activity data from clients, destinations, DNS, flows, associations, packets, routes, and traceroutes?')) return
      setBusy(true)
      try { const result = await clearObservationData({ clearActivityCache: clearActivity, refreshGatewayData: refresh }); onCleared(); setMessage(`Deleted ${Object.values(result.deleted).reduce((n, count) => n + count, 0).toLocaleString()} records.`) } catch (error) { setMessage(error instanceof Error ? error.message : 'Unable to clear data') } finally { setBusy(false) }
    }}>{busy ? 'Clearing data…' : 'Delete all observation data'}</button><p role="status">{message}</p></section>
  </dialog>
}
