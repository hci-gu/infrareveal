import { ArrowLeft, Maximize2, MoreHorizontal, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import type { CSSProperties } from 'react'
import { Link, useParams } from 'react-router-dom'
import { useStore } from 'zustand'
import { sessionTimelineStore, setTimelinePlayback, useFlowActivityRange, useGatewayData } from '@infrareveal/session-state'
import type { GatewayData } from '@infrareveal/session-state'
import { displayTimeZone } from '../../views/formatters'
import { SessionCompositionProjector } from '../../model/sessionModel'
import { usePreference, readPreference } from '../../shared/ui/preferences'
import { Splitter } from '../../shared/ui/Splitter'
import { captureCoverage } from '../../shared/activity/captureCoverage'
import { TrafficTimeline } from './TrafficTimeline'
import { TrafficTransport } from './TrafficTransport'
import { TrafficInspector } from './TrafficInspector'
import { TrafficLedger, type TrafficDock } from './TrafficLedger'
import { buildTrafficModel, trafficRecords, type TrafficSelection } from './trafficModel'
import { clampTime, inputHasOwnKeys, viewportAt } from './trafficTime'
import { useTrafficPlayback } from './useTrafficPlayback'
import { TrafficUtilities } from './TrafficUtilities'
import { TrafficTreemap } from './TrafficTreemap'
import { RECENT_TRAFFIC_MS, trafficVolumes, type TrafficImportanceMode } from './trafficImportance'
import { captureShortfalls, type LoadedTrafficRange } from './trafficCaptureQuality'
import '../../shared/ui/desktop.css'
import './traffic.css'

export function SessionPlaybackPage() {
  const { sessionID } = useParams()
  return <TrafficSession key={sessionID} requestedId={sessionID === 'active' ? undefined : sessionID} preferenceKey={sessionID || 'active'} />
}
function TrafficSession({ requestedId, preferenceKey }: { requestedId?: string; preferenceKey: string }) {
  const gateway = useGatewayData(requestedId)
  const { data, timeline } = gateway
  const session = data.selectedSession
  const runtimeCursor = useStore(sessionTimelineStore, state => state.cursorMs)
  const playback = useStore(sessionTimelineStore, state => state.playback)
  const prefix = `traffic.${preferenceKey}.`
  const [storedSpan, setSpan] = usePreference(prefix + 'window', 60_000)
  const span = [0, 10_000, 30_000, 60_000, 300_000].includes(storedSpan) ? storedSpan : 60_000
  const [collapsed, setCollapsed] = usePreference<string[]>(prefix + 'collapsed', [])
  const [storedImportance, setImportance] = usePreference<TrafficImportanceMode>(prefix + 'importance', 'total')
  const importance = ['total', 'recent', 'equal'].includes(storedImportance) ? storedImportance : 'total'
  const [contrast, setContrast] = usePreference(prefix + 'sizeContrast', 65)
  const [query, setQuery] = usePreference(prefix + 'query', '')
  const [client, setClient] = usePreference(prefix + 'client', 'all')
  const [storedSelected, setStoredSelected] = usePreference(prefix + 'selection', '')
  const [selection, setSelection] = useState<TrafficSelection | null>(() => storedSelected ? { kind: 'flow', id: storedSelected, flowId: storedSelected } : null)
  const [dock, setDock] = usePreference<TrafficDock>(prefix + 'dock', 'events')
  const [inspectorOpen, setInspectorOpen] = usePreference(prefix + 'inspector', true)
  const [dockOpen, setDockOpen] = usePreference(prefix + 'ledger', true)
  const [inspectorSize, setInspectorSize] = usePreference(prefix + 'inspectorWidth', 292)
  const [dockSize, setDockSize] = usePreference(prefix + 'ledgerHeight', 156)
  const [view, setView] = useState<'timeline' | 'treemap'>('timeline')
  const [utilities, setUtilities] = useState(false)
  const [expanded, setExpanded] = useState(false)
  const [reveal, setReveal] = useState(0)
  const [panCenter, setPanCenter] = useState<number | null>(null)
  const [visibleFlowIds, setVisibleFlowIds] = useState<string[]>([])
  const [projector] = useState(() => new SessionCompositionProjector())
  const rootRef = useRef<HTMLElement>(null)
  const initialized = useRef(false)
  const [initialCursor] = useState(() => {
    const value = Number(new URLSearchParams(window.location.search).get('at'))
    return value > 0 && Number.isFinite(value) ? value : readPreference(prefix + 'cursor', 0)
  })
  useEffect(() => {
    const narrow = window.matchMedia('(max-width: 950px)')
    const collapse = () => { if (narrow.matches) { setInspectorOpen(false); setDockOpen(false) } }
    collapse(); narrow.addEventListener('change', collapse)
    return () => narrow.removeEventListener('change', collapse)
  }, [setDockOpen, setInspectorOpen])
  const endMs = timeline.manifest?.active ? timeline.liveEdgeMs : Date.parse(timeline.manifest?.endedAt || timeline.manifest?.coverage.to || '')
  const bounds = useMemo(() => ({ fromMs: timeline.epochMs, toMs: Math.max(timeline.epochMs, Number.isFinite(endMs) ? endMs : timeline.epochMs) }), [endMs, timeline.epochMs])
  const cursorMs = clampTime(runtimeCursor, bounds)
  const viewportCenter = playback === 'playing' || playback === 'following'
    ? Math.floor((playback === 'following' ? bounds.toMs : cursorMs) / 5000) * 5000
    : panCenter ?? cursorMs
  const range = useMemo(() => viewportAt(viewportCenter, span, bounds), [bounds, viewportCenter, span])
  useTrafficPlayback(session?.id ?? null)
  useEffect(() => {
    if (!session || timeline.manifest?.sessionId !== session.id || requestedId && session.id !== requestedId || initialized.current) return
    initialized.current = true
    if (initialCursor) setTimelinePlayback({ cursorMs: clampTime(initialCursor, bounds), playback: 'paused' })
  }, [bounds, initialCursor, requestedId, session, timeline.manifest])
  useEffect(() => {
    const fromMs = Math.floor(range.fromMs / 5000) * 5000, toMs = Math.ceil(range.toMs / 5000) * 5000
    setTimelinePlayback({ viewport: { fromMs, toMs } })
  }, [range.fromMs, range.toMs])
  useEffect(() => {
    if (!session) return
    const timer = setInterval(() => {
      const state = sessionTimelineStore.getState()
      if (state.selectedSessionId !== session.id) return
      const url = new URL(window.location.href)
      url.searchParams.delete('session')
      url.searchParams.set('at', String(Math.round(state.cursorMs)))
      if (url.href !== window.location.href) window.history.replaceState(null, '', url)
      try { localStorage.setItem(`infrareveal.debug.v3.${prefix}cursor`, JSON.stringify(state.cursorMs)) } catch { /* Optional preference. */ }
    }, 1000)
    return () => clearInterval(timer)
  }, [prefix, session])
  const detailRange = useMemo(() => {
    const desired = range.toMs - range.fromMs > 15 * 60_000 ? viewportAt(cursorMs, 60_000, bounds) : range
    return { fromMs: Math.floor(desired.fromMs / 5000) * 5000, toMs: Math.ceil(desired.toMs / 5000) * 5000 }
  }, [bounds, cursorMs, range])
  const [loadedRange, setLoadedRange] = useState(detailRange)
  const { fromMs: requestFromMs, toMs: requestToMs } = detailRange
  useEffect(() => { const timer = setTimeout(() => setLoadedRange({ fromMs: requestFromMs, toMs: requestToMs }), 120); return () => clearTimeout(timer) }, [requestFromMs, requestToMs])
  const rangePending = loadedRange.fromMs !== detailRange.fromMs || loadedRange.toMs !== detailRange.toMs
  const requestedFlows = useMemo(() => [...new Set([...visibleFlowIds, ...(selection?.flowId ? [selection.flowId] : [])])].sort(), [selection, visibleFlowIds])
  const activity = useFlowActivityRange(session?.id ?? null, loadedRange.fromMs, loadedRange.toMs, requestedFlows)
  // A bounded, all-flow query avoids rewarding only the connections already visible.
  // Quantize loading to five seconds and ranking to one second, while the playhead stays smooth.
  const importanceCursor = Math.floor(cursorMs / 1000) * 1000
  const importanceActivity = useFlowActivityRange(importance === 'recent' ? session?.id ?? null : null,
    Math.floor((importanceCursor - RECENT_TRAFFIC_MS) / 5000) * 5000, Math.ceil(importanceCursor / 5000) * 5000)
  // Pin source evidence around the selected flow's start even if the viewport is later in its lifetime.
  const selectedFlow = data.flows.find(flow => flow.id === selection?.flowId)
  const evidenceTime = selectedFlow ? Date.parse(selectedFlow.start) : selection?.observedAtMs || 0
  const evidenceFrom = Math.floor((evidenceTime - 30_000) / 5000) * 5000
  // Include a short selected flow's whole history so its detail can be checked
  // against final counters. Long connections retain a bounded evidence request.
  const evidenceTo = Math.ceil(Math.min(evidenceFrom + 15 * 60_000, Math.max(evidenceTime + 30_000, selectedFlow ? Date.parse(selectedFlow.last_seen) + 5000 : 0)) / 5000) * 5000
  const evidence = useFlowActivityRange(evidenceTime && session ? session.id : null, evidenceFrom, evidenceTo, selection?.flowId ? requestedFlows : undefined)
  const combined = useMemo<GatewayData>(() => ({ ...data, routes: merge(data.routes, activity.routes, evidence.routes), dnsQueries: merge(data.dnsQueries, activity.dnsQueries, evidence.dnsQueries), flowActivityChunks: merge(activity.chunks, evidence.chunks), flowActivityWindows: merge(activity.windows, evidence.windows), gateEvents: merge(activity.gateEvents, evidence.gateEvents) }), [activity.routes, evidence.routes, activity.chunks, activity.dnsQueries, activity.gateEvents, activity.windows, data, evidence.chunks, evidence.dnsQueries, evidence.gateEvents, evidence.windows])
  const model = useMemo(() => buildTrafficModel(combined, projector, bounds.fromMs, bounds.toMs), [bounds.fromMs, bounds.toMs, combined, projector])
  const shortfalls = useMemo(() => {
    const loaded: LoadedTrafficRange[] = []
    if (session && !session.active && !gateway.error) {
      if (activity.loaded) loaded.push({ ...loadedRange, flowIds: requestedFlows })
      if (evidence.loaded && selection?.flowId) loaded.push({ fromMs: evidenceFrom, toMs: evidenceTo, flowIds: requestedFlows })
    }
    return captureShortfalls(model.clips, model.flows, loaded)
  }, [session, gateway.error, activity.loaded, loadedRange, requestedFlows, evidence.loaded, selection?.flowId, evidenceFrom, evidenceTo, model])
  const volumes = useMemo(() => trafficVolumes(model.flows, importance, importanceActivity.chunks, importanceActivity.windows, importanceCursor), [model.flows, importance, importanceActivity.chunks, importanceActivity.windows, importanceCursor])
  const records = useMemo(() => trafficRecords(combined), [combined])
  const search = query.trim().toLocaleLowerCase()
  const filteredGroups = useMemo(() => model.groups.map(group => ({ ...group,
    clips: group.clips.filter(clip => (client === 'all' || clip.clientIP === client) && `${clip.label} ${clip.flowId} ${clip.destinationIP} ${clip.clientIP}`.toLocaleLowerCase().includes(search)),
    dns: group.dns.filter(q => (client === 'all' || q.client_ip === client) && `${q.query_name} ${q.answers?.join(' ')} ${q.client_ip} ${q.id}`.toLocaleLowerCase().includes(search)),
    attributions: group.attributions.filter(a => (client === 'all' || group.client === client) && `${a.candidate_hostname} ${a.id} ${a.flow}`.toLocaleLowerCase().includes(search)),
    associations: group.associations.filter(a => (client === 'all' || group.client === client) && `${a.parent_label} ${a.id} ${a.flow}`.toLocaleLowerCase().includes(search)),
  })).filter(group => group.clips.length || group.dns.length || group.attributions.length || group.associations.length), [client, model.groups, search])
  const filteredRecords = useMemo(() => records.filter(record => (client === 'all' || record.client === client) && `${record.endpoint} ${record.client} ${record.selection.id} ${record.detail}`.toLocaleLowerCase().includes(search)), [client, records, search])
  const selectionFiltered = Boolean(selection && (selection.kind === 'flow'
    ? !filteredGroups.some(group => group.clips.some(clip => clip.flowId === selection.flowId))
    : !filteredRecords.some(record => record.selection.kind === selection.kind && record.selection.id === selection.id)))
  const coverage = useMemo(() => captureCoverage(combined.flowActivityWindows, range.fromMs, range.toMs), [combined.flowActivityWindows, range.fromMs, range.toMs])
  const navigatorCoverage = useMemo(() => captureCoverage(combined.flowActivityWindows, bounds.fromMs, bounds.toMs), [bounds.fromMs, bounds.toMs, combined.flowActivityWindows])
  const seek = useCallback((time: number) => { const next = clampTime(time, bounds); setPanCenter(null); setTimelinePlayback({ cursorMs: next, playback: 'paused' }) }, [bounds])
  const select = useCallback((next: TrafficSelection, time?: number) => {
    setSelection({ ...next, observedAtMs: time ?? records.find(r => r.selection.kind === next.kind && r.selection.id === next.id)?.time }); setStoredSelected(next.flowId || ''); setInspectorOpen(true); setReveal(value => value + 1)
    const group = model.groups.find(group => group.clips.some(clip => clip.flowId === next.flowId) || next.kind === 'dns' && group.dns.some(q => q.id === next.id))
    if (group) setCollapsed(previous => previous.filter(id => id !== group.id))
    if (time !== undefined) seek(time)
  }, [model.groups, records, seek, setCollapsed, setInspectorOpen, setStoredSelected])
  const visibleFlows = useCallback((ids: string[]) => { setVisibleFlowIds(previous => previous.join(',') === ids.join(',') ? previous : ids) }, [])
  const play = useCallback(() => { setPanCenter(null); setTimelinePlayback({ playback: playback === 'playing' || playback === 'following' ? 'paused' : 'playing', ...(cursorMs >= bounds.toMs ? { cursorMs: bounds.fromMs } : {}) }) }, [bounds, cursorMs, playback])
  const fold = useCallback((id: string) => setCollapsed(previous => previous.includes(id) ? previous.filter(item => item !== id) : [...previous, id]), [setCollapsed])
  const resetLayout = () => { setInspectorSize(292); setDockSize(156); setInspectorOpen(true); setDockOpen(true); setCollapsed([]); setSpan(60_000); setPanCenter(null); setImportance('total'); setContrast(65) }
  const known = !requestedId || data.sessions.some(item => item.id === requestedId)
  if (gateway.connectionState === 'loading') return <main className="desktop-ui"><div className="ui-empty"><h1>Loading Traffic…</h1><Link to="/">Back to Sessions</Link></div></main>
  if (!session || !known) return <main className="desktop-ui"><div className="ui-empty"><h1>{!known ? 'Session not found' : 'Traffic unavailable'}</h1><p>{gateway.error || 'Select a source from Sessions.'}</p><Link to="/">Back to Sessions</Link><button type="button" onClick={() => void gateway.refresh()}>Retry</button></div></main>
  return <main ref={rootRef} tabIndex={-1} className={`desktop-ui traffic-workspace ${expanded ? 'expanded' : ''} ${inspectorOpen ? '' : 'inspector-closed'} ${dockOpen ? '' : 'ledger-closed'}`} style={{ '--inspector-width': `${Math.max(240, Math.min(440, inspectorSize))}px`, '--ledger-height': `${Math.max(110, Math.min(350, dockSize))}px` } as CSSProperties} onKeyDown={event => {
    if (event.key === 'Escape') { setExpanded(false); return }
    if (inputHasOwnKeys(event.target)) return
    if (event.code === 'Space') { event.preventDefault(); play() }
    if (event.key === 'ArrowLeft' || event.key === 'ArrowRight') { event.preventDefault(); seek(cursorMs + (event.key === 'ArrowLeft' ? -1 : 1) * (event.shiftKey ? 5000 : 1000)) }
  }}>
    <header className="traffic-windowbar"><div><span className={`connection-dot ${gateway.connectionState}`} /><h1>Traffic <span>/ {session.name || session.id}</span></h1></div><div><span>{session.active ? 'LIVE SESSION' : 'RECORDED SESSION'}</span><span>{gateway.connectionState === 'offline' || gateway.error ? 'Gateway offline' : session.active ? 'Recording' : 'Recording ended'}</span><button type="button" aria-label={expanded ? 'Exit expanded Traffic' : 'Expand Traffic'} title="Expand workspace" onClick={() => { setExpanded(value => !value); rootRef.current?.focus() }}><Maximize2 size={14} /></button></div></header>
    <nav className="traffic-toolbar" aria-label="Traffic tools"><Link className="ui-button" to="/"><ArrowLeft size={13} /> Sessions</Link><input aria-label="Filter Traffic endpoints" type="search" placeholder="Find an endpoint or address…" value={query} onChange={event => setQuery(event.target.value)} /><select aria-label="Filter Traffic client" value={client} onChange={event => setClient(event.target.value)}><option value="all">All clients</option>{[...new Set(data.flows.map(flow => flow.client_ip))].sort().map(ip => <option key={ip}>{ip}</option>)}{client !== 'all' && !data.flows.some(f => f.client_ip === client) ? <option value={client}>{client} · not observed</option> : null}</select><span className="toolbar-space" /><button type="button" aria-pressed={dockOpen} onClick={() => setDockOpen(value => !value)}>Events</button><button type="button" aria-pressed={inspectorOpen} onClick={() => setInspectorOpen(value => !value)}>Inspector</button><button type="button" aria-label="Refresh Traffic" onClick={() => void gateway.refresh()}><RefreshCw size={14} /></button><button type="button" aria-label="Traffic utilities" onClick={() => setUtilities(true)}><MoreHorizontal size={17} /></button></nav>
    {gateway.error ? <div className="ui-notice warning" role="status">{gateway.error} · Retaining loaded observations.</div> : null}
    <div className="traffic-body"><div className="traffic-main-pane">
      {view === 'timeline' ? <TrafficTimeline preferenceKey={prefix} groups={filteredGroups} flows={model.flows} shortfalls={shortfalls} range={range} cursorMs={cursorMs} coverage={coverage} collapsed={collapsed} selected={selection} reveal={reveal} importance={importance} contrast={contrast} volumes={volumes} importanceLoading={importance === 'recent' && importanceActivity.loading} importanceError={importance === 'recent' ? importanceActivity.error : null} onImportance={setImportance} onContrast={setContrast} onFold={fold} onSelect={select} onSeek={seek} onVisibleFlows={visibleFlows} onPan={delta => { setTimelinePlayback({ playback: 'paused' }); setPanCenter(clampTime((range.fromMs + range.toMs) / 2 + delta, bounds)) }} /> : <TrafficTreemap composition={model.composition} cursorMs={cursorMs} onSelect={select} />}
      <TrafficTransport bounds={bounds} range={range} cursorMs={cursorMs} playing={playback === 'playing' || playback === 'following'} following={playback === 'following'} live={session.active} rate={timeline.rate} span={span} coverage={navigatorCoverage} onSeek={seek} onPlay={play} onLive={() => { setPanCenter(null); setTimelinePlayback({ cursorMs: bounds.toMs, playback: session.active ? 'following' : 'paused' }) }} onRate={rate => setTimelinePlayback({ rate })} onSpan={value => { setSpan(value); setPanCenter(null) }} />
      {dockOpen ? <><Splitter label="Resize event ledger" axis="horizontal" value={dockSize} min={110} max={350} onChange={setDockSize} /><TrafficLedger records={filteredRecords} tab={['events','dns','flows'].includes(dock) ? dock : 'events'} onTab={setDock} selected={selection} onSelect={select} /></> : null}
    </div>{inspectorOpen ? <><Splitter label="Resize Traffic inspector" axis="vertical" value={inspectorSize} min={240} max={440} onChange={setInspectorSize} /><TrafficInspector cursorMs={cursorMs} shortfall={selection?.flowId ? shortfalls.get(selection.flowId) : undefined} data={combined} selected={selection} records={records} range={range} loading={rangePending || activity.loading || evidence.loading} error={activity.error || evidence.error} filtered={selectionFiltered} /></> : null}</div>
    <footer className="desktop-status"><span>{playback === 'following' ? 'Following live edge' : playback === 'playing' ? 'Playing' : 'View paused'} · {session.active ? 'Capture continues independently' : 'Fixed recording end'}{activity.loading || rangePending ? ' · Loading detail…' : ''}</span><span className={shortfalls.size || coverage.some(c => c.level === 'partial' || c.level === 'unavailable') ? 'quality-warning' : ''}>Capture: {shortfalls.size ? 'activity does not match flow totals' : coverage.some(c => c.level === 'unavailable') ? 'unavailable intervals' : coverage.some(c => c.level === 'partial') ? 'incomplete intervals' : coverage.some(c => c.level === 'unknown') ? 'unknown / unloaded intervals' : 'complete window'}{activity.error ? ' · Detail error' : ''}</span><span>{model.clips.length.toLocaleString()} observed flows · {displayTimeZone}</span></footer>
    <TrafficUtilities open={utilities} onClose={() => setUtilities(false)} view={view} onView={setView} onReset={resetLayout} composition={model.composition} range={range} selectedId={selection?.flowId ? `clip:${selection.flowId}` : null} session={session} clearActivity={activity.clear} refresh={gateway.refresh} onCleared={() => { setSelection(null); setStoredSelected('') }} />
  </main>
}
function merge<T extends { id: string }>(...lists: T[][]): T[] { return [...new Map(lists.flat().map(item => [item.id, item])).values()] }
export default SessionPlaybackPage
