import { formatClock } from '../../views/formatters'
import { ArrowLeft, Maximize2, RefreshCw, Minus, Plus, Focus } from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { useStore } from 'zustand'
import { observeTimelineLiveEdge, sessionTimelineStore, setTimelinePlayback, useFlowActivityRange, useGatewayData } from '@infrareveal/session-state'
import { DEMO_EPOCH_MS } from './constants'
import { GateArmDialog } from './components/GateArmDialog'
import { GateHealth } from './components/GateHealth'
import { QueueInspector } from './components/QueueInspector'
import { GraphViewport } from './components/GraphViewport'
import { DEFAULT_GRAPH_TRANSFORM } from './model/graphViewState'
import { NodeInspector } from './components/NodeInspector'
import { LabReplayControls } from './components/LabReplayControls'
import { useLabPlayback } from './state/useLabPlayback'
import { demoPipelineEnvelope, isProxyLabDemoEnabled } from './data/demoTransport'
import { TraceClient } from './data/traceClient'
import { gapEvent, mergeLiveEvents } from './model/mergeLiveEvents'
import { deriveActivityDataQuality } from './model/activityDataQuality'
import { RecordedEventProjector } from './model/projectRecordedEvents'
import { buildLabTraces, preferredTraceEvent, stepTraceNode, traceEventPath, traceKey } from './model/traceNavigation'
import { usePreference, readPreference } from '../../shared/ui/preferences'
import { useLabControl } from './state/useLabControl'
import { clearProxyLabRoute, addEphemeralEvents, applyTraceMessageMetadata, proxyLabStore, resetProxyLabSession, selectProxyLabEvent, setOperatorToken, setTraceConnection, setLabGateMode, setLabObservationMode, selectLabNode } from './state/proxyLabStore'
import type { PipelineEvent } from './types'
import './lab.css'

export function ProxyLabPage() {
  const { sessionID = '' } = useParams()
  const location = useLocation()
  const demo = isProxyLabDemoEnabled(location.search, import.meta.env.DEV, import.meta.env.VITE_PROXY_LAB_DEMO)
  return <LabSession key={`${sessionID}:${demo}`} sessionID={sessionID} demo={demo} />
}
function LabSession({ sessionID, demo }: { sessionID: string; demo: boolean }) {
  const gateway = useGatewayData(sessionID, !demo)
  const { data, timeline } = gateway
  const playback = useStore(sessionTimelineStore, state => state.playback)
  const rate = useStore(sessionTimelineStore, state => state.rate)
  const runtimeCursor = useStore(sessionTimelineStore, state => state.cursorMs)
  const liveEdgeMs = useStore(sessionTimelineStore, state => state.liveEdgeMs)
  const lab = useStore(proxyLabStore, state => state)
  const [projector] = useState(() => new RecordedEventProjector())
  const [query, setQuery] = usePreference(`lab.${sessionID}.query`, '')
  const [client, setClient] = usePreference(`lab.${sessionID}.client`, 'all')
  const [protocol, setProtocol] = usePreference(`lab.${sessionID}.protocol`, 'all')
  const [branches, setBranches] = usePreference(`lab.${sessionID}.branches`, true)
  const [transform, setTransform] = usePreference(`lab.${sessionID}.graph`, DEFAULT_GRAPH_TRANSFORM)
  const [storedTrace, setStoredTrace] = usePreference(`lab.${sessionID}.trace`, '')
  const [expanded, setExpanded] = useState(false)
  const [asideOpen, setAsideOpen] = useState(() => window.innerWidth > 950)
  const [reduceMotion, setReduceMotion] = useState(() => window.matchMedia('(prefers-reduced-motion: reduce)').matches)
  const initialized = useRef(false)
  const root = useRef<HTMLElement>(null)
  const [initialCursor] = useState(() => Number(new URLSearchParams(window.location.search).get('at')) || readPreference(`lab.${sessionID}.cursor`, 0))
  useEffect(() => { resetProxyLabSession(sessionID); return clearProxyLabRoute }, [sessionID])
  useEffect(() => {
    const narrow = window.matchMedia('(max-width: 950px)')
    const collapse = () => { if (narrow.matches) setAsideOpen(false) }
    narrow.addEventListener('change', collapse); return () => narrow.removeEventListener('change', collapse)
  }, [])
  const activeSession = !demo && Boolean(data.selectedSession?.active)
  const epochMs = demo ? DEMO_EPOCH_MS : timeline.epochMs
  const endMs = demo ? demoPipelineEnvelope.serverNowMs : activeSession ? Math.max(epochMs, liveEdgeMs) : Math.max(epochMs, Date.parse(timeline.manifest?.endedAt || timeline.manifest?.coverage.to || '') || epochMs)
  const cursorMs = Math.min(endMs, Math.max(epochMs, runtimeCursor))
  const detailFromMs = Math.floor(Math.max(epochMs, cursorMs - 15_000) / 5000) * 5000
  const detailToMs = Math.ceil(Math.min(endMs || cursorMs + 15_000, cursorMs + 15_000) / 5000) * 5000
  const [loadedRange, setLoadedRange] = useState({ from: detailFromMs, to: detailToMs })
  useEffect(() => { const timer = setTimeout(() => setLoadedRange({ from: detailFromMs, to: Math.max(detailFromMs + 1, detailToMs) }), 120); return () => clearTimeout(timer) }, [detailFromMs, detailToMs])
  const activity = useFlowActivityRange(demo ? null : sessionID, loadedRange.from, loadedRange.to)
  const control = useLabControl(sessionID, activeSession && !demo, pocketBaseURL())
  useLabPlayback({ sessionId: sessionID, epochMs, endMs, active: activeSession, demo })
  useEffect(() => {
    if (initialized.current || (!demo && (timeline.manifest?.sessionId !== sessionID || data.selectedSession?.id !== sessionID))) return
    initialized.current = true
    setLabObservationMode(activeSession && !initialCursor ? 'live-observe' : 'replay')
    setTimelinePlayback({ cursorMs: Math.min(endMs, Math.max(epochMs, initialCursor || (activeSession ? endMs : epochMs))), playback: activeSession && !initialCursor ? 'following' : 'paused' })
  }, [activeSession, data.selectedSession?.id, demo, endMs, epochMs, initialCursor, sessionID, timeline.manifest])
  useEffect(() => { setTimelinePlayback({ viewport: { fromMs: detailFromMs, toMs: Math.max(detailFromMs + 1, detailToMs) } }) }, [detailFromMs, detailToMs])
  useEffect(() => {
    const media = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReduceMotion(media.matches)
    media.addEventListener('change', update); return () => media.removeEventListener('change', update)
  }, [])
  useEffect(() => {
    const timer = setInterval(() => {
      const state = sessionTimelineStore.getState()
      if (!demo && state.selectedSessionId !== sessionID) return
      const url = new URL(window.location.href); url.searchParams.set('at', String(Math.round(state.cursorMs)))
      window.history.replaceState(null, '', url)
      try { localStorage.setItem(`infrareveal.debug.v3.lab.${sessionID}.cursor`, JSON.stringify(state.cursorMs)) } catch { /* Optional preference. */ }
    }, 1000)
    return () => clearInterval(timer)
  }, [demo, sessionID])
  const recordedEvents = useMemo(() => demo ? demoPipelineEnvelope.events : timeline.manifest?.sessionId !== sessionID || loadedRange.from > endMs || loadedRange.to < epochMs ? [] : projector.project({ ...data, dnsQueries: activity.dnsQueries, flowActivityChunks: activity.chunks, flowActivityWindows: activity.windows }, activity.gateEvents, { fromMs: loadedRange.from - 30_000, toMs: loadedRange.to + 30_000 }), [activity.chunks, activity.dnsQueries, activity.gateEvents, activity.windows, data, demo, endMs, epochMs, loadedRange, projector, sessionID, timeline.manifest?.sessionId])
  const clearActivity = activity.clear, refreshGateway = gateway.refresh
  useEffect(() => {
    if (demo || !activeSession || lab.observationMode === 'replay') { setTraceConnection('idle'); return }
    const client = new TraceClient({ sessionId: sessionID, token: lab.operatorToken || undefined, baseUrl: pocketBaseURL() })
    let disposed = false
    client.start({
      onState: state => { if (!disposed) setTraceConnection(state) },
      onError: error => { if (!disposed) setTraceConnection('error', error.message) },
      onMessage: message => {
        if (disposed) return
        applyTraceMessageMetadata(message)
        if (message.type === 'gap') { addEphemeralEvents([gapEvent(message)]); setTraceConnection('gap'); clearActivity(); void refreshGateway(); return }
        if (message.events.length) { addEphemeralEvents(message.events); observeTimelineLiveEdge(message.events.reduce((max, event) => Math.max(max, event.occurredAtMs), 0), message.serverNowMs) }
      },
    })
    return () => { disposed = true; client.stop() }
  }, [activeSession, clearActivity, demo, lab.observationMode, lab.operatorToken, refreshGateway, sessionID])
  const allEvents = useMemo(() => mergeLiveEvents(recordedEvents, lab.ephemeralEvents.values(), endMs), [endMs, lab.ephemeralEvents, recordedEvents])
  const visualEvents = useMemo(() => allEvents.filter(e => e.kind !== 'health'), [allEvents])
  const traces = useMemo(() => buildLabTraces(visualEvents), [visualEvents])
  const filtered = useMemo(() => traces.filter(trace => (client === 'all' || trace.client === client) && (protocol === 'all' || trace.protocol.toLowerCase() === protocol) && `${trace.label} ${trace.client} ${trace.id}`.toLowerCase().includes(query.trim().toLowerCase())), [client, protocol, query, traces])
  const traceId = lab.selectedTraceId || storedTrace
  const trace = traces.find(t => t.id === traceId)
  useEffect(() => {
    if (!traceId && filtered.length) { selectProxyLabEvent(null, filtered[0].id); setStoredTrace(filtered[0].id) }
  }, [filtered, setStoredTrace, traceId])
  const selectedEvent = trace?.events.find(e => e.id === lab.selectedEventId) ?? preferredTraceEvent(trace, cursorMs)
  const path = traceEventPath(selectedEvent)
  const stage = lab.selectedNodeId && path ? path.nodes.indexOf(lab.selectedNodeId) : -1
  const captureStatus = data.flowActivityStatuses.filter(s => s.session === sessionID).sort((a,b) => Date.parse(b.reported_at) - Date.parse(a.reported_at))[0]
  const quality = useMemo(() => deriveActivityDataQuality({ cursorMs, windows: activity.windows, status: captureStatus, healthEvents: allEvents.filter(e => e.kind === 'health'), streamDropped: demo ? 0 : lab.traceDropped, traceConnection: demo ? 'idle' : lab.traceConnection, usesLiveStream: activeSession && lab.observationMode === 'live-observe', atLiveEdge: activeSession && (playback === 'following' || endMs - cursorMs <= 1000) }), [activeSession, activity.windows, allEvents, captureStatus, cursorMs, demo, endMs, lab.observationMode, lab.traceConnection, lab.traceDropped, playback])
  const seek = (time: number) => setTimelinePlayback({ cursorMs: Math.min(endMs, Math.max(epochMs, time)), playback: 'paused' })
  const selectEvent = (event: PipelineEvent) => { selectProxyLabEvent(event.id, traceKey(event)); setStoredTrace(traceKey(event)); seek(event.occurredAtMs) }
  const selectTrace = (id: string) => { selectProxyLabEvent(null, id); setStoredTrace(id); selectLabNode(null) }
  const actionable = activeSession && !demo && lab.controlConnection === 'ready' && Boolean(lab.operatorToken) && lab.gateStatus?.sessionId === sessionID && Boolean(lab.gateStatus.armed)
  const audit = timeline.manifest?.gateAuditComplete
  const candidates = [...new Set([...data.flows.map(f => f.client_ip), ...visualEvents.flatMap(e => e.summary.clientIp ? [e.summary.clientIp] : [])])].sort()
  if (!demo && gateway.connectionState === 'loading') return <StatePage title="Loading Lab" detail="Preparing session evidence…" />
  if (!demo && !data.sessions.some(s => s.id === sessionID)) return <StatePage title="Session not found" detail={gateway.error || `No session with ID ${sessionID} is available.`} />
  return <main ref={root} tabIndex={-1} className={`lab-workspace ${expanded ? 'expanded' : ''} ${asideOpen ? '' : 'aside-closed'}`} onKeyDown={e => { if (e.key === 'Escape') setExpanded(false) }}>
    <header className="lab-header"><div><Link to="/" aria-label="Back to Sessions"><ArrowLeft size={18} /></Link><div><h1>Flow laboratory</h1><p>{demo ? 'Deterministic demo · no live control connection' : data.selectedSession?.name || sessionID} <span>· {activeSession ? 'Live source' : 'Recorded source'}</span></p></div></div><div className="lab-head-actions"><div className="lab-observation-mode" role="group" aria-label="Lab observation mode"><button type="button" disabled={!activeSession} aria-pressed={lab.observationMode === 'live-observe'} onClick={() => { setLabObservationMode('live-observe'); setTimelinePlayback({ cursorMs: endMs, playback: 'following' }) }}>Live observe</button><button type="button" aria-pressed={lab.observationMode === 'replay'} onClick={() => { setLabObservationMode('replay'); setTimelinePlayback({ playback: 'paused' }) }}>Replay</button></div><button type="button" aria-label="Refresh Lab" onClick={() => void gateway.refresh()}><RefreshCw size={16} /></button><button type="button" aria-label={expanded ? 'Exit expanded Lab' : 'Expand Lab'} onClick={() => { setExpanded(!expanded); root.current?.focus() }}><Maximize2 size={17} /></button></div></header>
    <div className="lab-tools"><label>Trace <input type="search" aria-label="Search Lab traces" placeholder="Find an endpoint…" value={query} onChange={e => setQuery(e.target.value)} /></label><select aria-label="Filter Lab client" value={client} onChange={e => setClient(e.target.value)}><option value="all">All clients</option>{candidates.map(ip => <option key={ip}>{ip}</option>)}{client !== 'all' && !candidates.includes(client) ? <option value={client}>{client} · not observed</option> : null}</select><select aria-label="Filter Lab protocol" value={protocol} onChange={e => setProtocol(e.target.value)}><option value="all">All protocols</option>{[...new Set(traces.map(t => t.protocol.toLowerCase()).filter(Boolean))].sort().map(p => <option key={p} value={p}>{p.toUpperCase()}</option>)}{protocol !== 'all' && !traces.some(t => t.protocol.toLowerCase() === protocol) ? <option value={protocol}>{protocol.toUpperCase()} · not observed</option> : null}</select><label className="lab-branch-toggle"><input type="checkbox" checked={branches} onChange={e => setBranches(e.target.checked)} /> Observation branches</label><span className="lab-tools-space"/><button type="button" aria-pressed={asideOpen} onClick={() => setAsideOpen(!asideOpen)}>Inspector / NOW</button></div>
    {gateway.error || activity.error || lab.traceError || lab.controlError ? <p className="lab-notice" role="status">{lab.controlError || lab.traceError || activity.error || gateway.error} · Loaded evidence retained.</p> : null}
    <div className="lab-main"><section className="lab-stage"><div className="lab-trace-selector"><select aria-label="Selected Lab trace" value={traceId || ''} onChange={e => selectTrace(e.target.value)}><option value="" disabled>Select a trace</option>{filtered.slice(0, 500).map(t => <option key={t.id} value={t.id}>{t.client || 'Client unknown'} · {t.label}</option>)}{traceId && !filtered.slice(0,500).some(t => t.id === traceId) ? <option value={traceId}>{trace?.label || traceId} · {trace ? 'outside filter' : 'outside loaded history'}</option> : null}</select><span>{filtered.length.toLocaleString()} traces{filtered.length > 500 ? ' · first 500, refine search' : ''}</span><div className="lab-zoom"><button type="button" aria-label="Zoom out Lab graph" onClick={() => setTransform(t => ({ ...t, zoom: Math.max(.65, t.zoom / 1.2) }))}><Minus size={14}/></button><button type="button" aria-label="Fit path" onClick={() => setTransform(DEFAULT_GRAPH_TRANSFORM)}><Focus size={14}/> Fit path</button><button type="button" aria-label="Zoom in Lab graph" onClick={() => setTransform(t => ({ ...t, zoom: Math.min(3, t.zoom * 1.2) }))}><Plus size={14}/></button><button type="button" onClick={() => { setTransform(DEFAULT_GRAPH_TRANSFORM); setBranches(true) }}>Reset view</button></div></div>
      {!filtered.length ? <div className="lab-empty-notice">{traces.length ? 'No traces match these filters. Selected evidence is retained.' : 'No trace evidence is loaded for this interval. Move the replay position or refresh.'}</div> : null}
      <GraphViewport events={visualEvents} cursorMs={cursorMs} selectedEventId={selectedEvent?.id || null} path={path} selectedNode={lab.selectedNodeId} branches={branches} transform={transform} onTransform={setTransform} onSelect={id => { selectLabNode(id); setAsideOpen(true) }} reduceMotion={reduceMotion} />
      <div className="lab-trace-navigation"><div><strong>{lab.selectedNodeId ? `Trace in focus · ${lab.selectedNodeId.replace(/_/g,' ')}` : trace ? 'Follow this trace through the gateway' : 'Select a trace to follow its path'}</strong><p>{selectedEvent ? `${selectedEvent.kind} / ${selectedEvent.stage} · ${selectedEvent.timing === 'derived' ? 'Derived timing' : 'Observed event; intermediate stages reconstructed'}` : 'Node selection and replay position remain independent.'}</p></div><span>{stage >= 0 ? stage + 1 : '—'} / {path?.nodes.length || '—'}</span><button type="button" disabled={!path || stage === 0} onClick={() => selectLabNode(stepTraceNode(path, lab.selectedNodeId, -1))}>← Previous</button><button type="button" className="lab-primary" disabled={!path || stage === path.nodes.length - 1} onClick={() => selectLabNode(stepTraceNode(path, lab.selectedNodeId, 1))}>Next stage →</button></div>
      {trace ? <label className="lab-event-picker">Source event <select aria-label="Selected trace event" value={selectedEvent?.id || ''} onChange={e => { const event = trace.events.find(event => event.id === e.target.value); if (event) selectEvent(event) }}>{trace.events.slice(-1000).map(e => <option key={e.id} value={e.id}>{formatClock(e.occurredAtMs)} · {e.kind} / {e.stage} · {e.summary.verdict || e.timing}</option>)}{selectedEvent && !trace.events.slice(-1000).some(e => e.id === selectedEvent.id) ? <option value={selectedEvent.id}>{selectedEvent.id}</option> : null}</select></label> : null}
      <LabReplayControls epochMs={epochMs} endMs={endMs} cursorMs={cursorMs} playback={playback} rate={rate} active={activeSession} events={trace?.events || visualEvents} onSeek={seek}/>
    </section>{asideOpen ? <aside className="lab-aside"><NodeInspector nodeId={lab.selectedNodeId} events={trace?.events || []} selectedEvent={selectedEvent} data={{ ...data, dnsQueries: activity.dnsQueries }} onEvent={selectEvent}/>
      {activeSession ? <><QueueInspector actionable={actionable} decisions={[...lab.pendingDecisions.values()]} events={visualEvents} gateMode={lab.gateStatus?.mode || null} historical={playback !== 'following'} inFlight={lab.controlInFlight} nowMs={control.nowMs} onApprove={id => void control.decide(id, 'accept')} onReject={id => void control.decide(id, 'drop')} onAcceptNext={count => void control.acceptNext(count)} onApproveAll={() => void control.approveAll()} recent={lab.recentDecisions} onSelect={(_, id) => selectTrace(id)}/>
        <div className="lab-control-status"><strong>Control {lab.controlConnection} · {lab.gateStatus?.state || 'unavailable'}</strong><p>{lab.gateStatus?.armed ? `${lab.gateStatus.mode} · ${lab.gateStatus.clientIps.join(', ')} · session ${lab.gateStatus.sessionId}` : 'No armed gate reported.'}</p>{!lab.operatorToken ? <p>Enter an operator token in Gate setup to load current decisions.</p> : null}</div>
        <details className="lab-gate-setup"><summary>Gate setup &amp; controls</summary><label>Requested mode <select aria-label="Requested gate mode" value={lab.requestedGateMode} onChange={e => setLabGateMode(e.target.value as 'flow'|'strict'|'dns')}><option value="flow">Flow admission</option><option value="strict">Strict packet stepping</option><option value="dns">DNS gate</option></select></label><GateArmDialog busy={lab.controlInFlight.size > 0} available={activeSession && lab.controlConnection === 'ready'} candidateClients={candidates} mode={lab.requestedGateMode === 'flow' ? 'turn-based' : lab.requestedGateMode} onArm={(ips, mode, strict) => void control.arm(ips,mode,strict)} onToken={setOperatorToken} sessionId={sessionID} status={lab.gateStatus} token={lab.operatorToken}/><GateHealth actionable={actionable} busy={() => lab.controlInFlight.size > 0} controlStatus={lab.controlConnection} streamDropped={lab.traceDropped} onDisarm={() => void control.disarm()} onDrain={() => void control.drain()} onPause={() => void control.pause()} onResume={() => void control.resume()} status={lab.gateStatus} traceStatus={lab.traceConnection}/></details>
      </> : <section className="lab-recorded-audit"><h2>{demo ? 'Demo gate evidence' : 'Recorded gate audit'}</h2><p>{demo ? 'Fixture events are illustrative; real control requests are disabled.' : `Audit ${audit === true ? 'complete' : audit === false ? 'incomplete' : 'quality unknown'}. Current decision actions are unavailable for recordings.`}</p>{visualEvents.filter(e => e.kind === 'gate').slice(-30).map(e => <button type="button" key={e.id} onClick={() => selectEvent(e)}>{e.summary.verdict || 'Queued'} · {formatClock(e.occurredAtMs)}<span>{e.summary.verdictSource || 'Source event'} · {e.summary.flowKey || e.traceId}</span></button>)}</section>}
      <details className="lab-quality-details"><summary>Evidence quality &amp; provenance</summary><p>Capture: {quality.capture.detail}</p><p>Browser stream: {quality.stream.detail}</p><p>Durable gate audit: {demo ? 'Fixture' : audit === true ? 'Complete' : audit === false ? `Incomplete · ${timeline.manifest?.gateAuditDrops ?? 'unknown'} lost items` : 'Unknown'}</p><p>Capture gaps, browser delivery loss and missing durable audit are separate. Absence of evidence is not confirmed idleness.</p><Link to="/controlled-client">Controlled client</Link></details><p className="sr-only" aria-live="polite">{lab.announcement}</p>
    </aside> : null}</div>
    <footer className="lab-status"><span>{demo ? 'DEMO · no live control' : `${activeSession ? 'Live' : 'Recorded'} source · ${gateway.connectionState === 'live' ? 'Gateway connected' : gateway.connectionState}`}</span><span title={quality.capture.detail}>Capture: {quality.capture.label}</span><span title={quality.stream.detail}>Trace: {quality.stream.label}</span><span className={audit === false || lab.gateStatus?.auditDrops ? 'danger' : ''}>Gate audit: {audit === false || lab.gateStatus?.auditDrops ? 'Incomplete' : audit === true ? 'Complete' : 'Unknown'}</span>{reduceMotion ? <span>Reduced motion · static direction indicators</span> : null}</footer>
  </main>
}
function StatePage({ title, detail }: { title: string; detail: string }) { return <main className="lab-workspace lab-state"><h1>{title}</h1><p>{detail}</p><Link to="/">Back to Sessions</Link></main> }
function pocketBaseURL() { return (import.meta.env.VITE_POCKETBASE_URL || `${window.location.protocol}//${window.location.hostname}:8090`).replace(/\/$/, '') }
