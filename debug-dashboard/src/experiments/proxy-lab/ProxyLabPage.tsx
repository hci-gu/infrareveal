import { ArrowLeft, Network, RefreshCw } from 'lucide-react'
import { useEffect, useMemo, useState } from 'react'
import { Link, useLocation, useParams } from 'react-router-dom'
import { useStore } from 'zustand'
import {
  FPS,
  observeTimelineLiveEdge,
  sessionTimelineStore,
  useFlowActivityRange,
  useGatewayData,
} from '@infrareveal/session-state'
import { DEMO_EPOCH_MS } from './constants'
import { GateArmDialog } from './components/GateArmDialog'
import { GateHealth } from './components/GateHealth'
import { ModeSwitcher } from './components/ModeSwitcher'
import { PipelineFilters } from './components/PipelineFilters'
import { PipelinePlayer } from './components/PipelinePlayer'
import { QueueInspector } from './components/QueueInspector'
import { demoPipelineEnvelope, isProxyLabDemoEnabled } from './data/demoTransport'
import { GateAPIError, GateClient } from './data/gateClient'
import { TraceClient } from './data/traceClient'
import { gapEvent, mergeLiveEvents } from './model/mergeLiveEvents'
import { deriveActivityDataQuality } from './model/activityDataQuality'
import { RecordedEventProjector } from './model/projectRecordedEvents'
import { selectFilteredEvents } from './state/selectors'
import {
  clearProxyLabRoute,
  completeGateDecision,
  addEphemeralEvents,
  applyTraceMessageMetadata,
  proxyLabStore,
  resetProxyLabSession,
  selectProxyLabEvent,
  setControlError,
  setControlConnection,
  setControlInFlight,
  setGateStatus,
  setOperatorToken,
  setProxyLabFilters,
  setProxyLabMode,
  setTraceConnection,
  synchronizePendingDecisions,
} from './state/proxyLabStore'
import type { PipelineEvent } from './types'

export function ProxyLabPage() {
  const { sessionID = '' } = useParams()
  const location = useLocation()
  const demo = isProxyLabDemoEnabled(location.search, import.meta.env.DEV, import.meta.env.VITE_PROXY_LAB_DEMO)
  const gateway = useGatewayData(sessionID, !demo)
  const playback = useStore(sessionTimelineStore, (state) => state.playback)
  const rate = useStore(sessionTimelineStore, (state) => state.rate)
  const cursorMs = useStore(sessionTimelineStore, (state) => state.cursorMs)
  const liveEdgeMs = useStore(sessionTimelineStore, (state) => state.liveEdgeMs)
  const viewport = useStore(sessionTimelineStore, (state) => state.viewport)
  const lab = useStore(proxyLabStore, (state) => state)
  const [projector] = useState(() => new RecordedEventProjector())
  const [nowMs, setNowMs] = useState(() => Date.now())
  const reduceMotion = usePrefersReducedMotion()

  useEffect(() => {
    resetProxyLabSession(sessionID)
    return clearProxyLabRoute
  }, [sessionID])

  const epochMs = demo ? DEMO_EPOCH_MS : gateway.timeline.epochMs
  const detailFromMs = viewport.toMs > viewport.fromMs ? viewport.fromMs : Math.max(epochMs, cursorMs - 15_000)
  const detailToMs = viewport.toMs > viewport.fromMs ? viewport.toMs : Math.max(detailFromMs + 30_000, cursorMs + 15_000)
  const activity = useFlowActivityRange(demo ? null : sessionID, detailFromMs, detailToMs)
  const activeSession = Boolean(gateway.data.selectedSession?.active)
  const clearActivity = activity.clear
  const refreshGateway = gateway.refresh
  const gateClient = useMemo(() => new GateClient(lab.operatorToken, pocketBaseURL()), [lab.operatorToken])

  const recordedEvents = useMemo(() => {
    if (demo) return demoPipelineEnvelope.events
    return projector.project({
      ...gateway.data,
      dnsQueries: activity.dnsQueries,
      flowActivityChunks: activity.chunks,
      flowActivityWindows: activity.windows,
    }, activity.gateEvents, { fromMs: detailFromMs - 30_000, toMs: detailToMs + 30_000 })
  }, [activity.chunks, activity.dnsQueries, activity.gateEvents, activity.windows, demo, detailFromMs, detailToMs, gateway.data, projector])

  useEffect(() => {
    if (demo || !activeSession || lab.mode === 'replay') {
      setTraceConnection('idle')
      return
    }
    const client = new TraceClient({
      sessionId: sessionID,
      token: lab.operatorToken || undefined,
      baseUrl: pocketBaseURL(),
    })
    client.start({
      onState: (state) => setTraceConnection(state),
      onError: (error) => setTraceConnection('error', error.message),
      onMessage: (message) => {
        applyTraceMessageMetadata(message)
        if (message.type === 'gap') {
          addEphemeralEvents([gapEvent(message)])
          setTraceConnection('gap')
          clearActivity()
          void refreshGateway()
          return
        }
        if (message.events.length > 0) {
          addEphemeralEvents(message.events)
          const newestOccurredAt = Math.max(...message.events.map((event) => event.occurredAtMs))
          observeTimelineLiveEdge(newestOccurredAt, message.serverNowMs)
        }
      },
    })
    return () => client.stop()
  }, [activeSession, clearActivity, demo, lab.mode, lab.operatorToken, refreshGateway, sessionID])

  useEffect(() => {
    if (demo || !activeSession) {
      setControlConnection('idle')
      setGateStatus(null)
      synchronizePendingDecisions([])
      return
    }
    const controller = new AbortController()
    let first = true
    const reconcile = async () => {
      if (first) setControlConnection('connecting')
      try {
        const status = await gateClient.status(controller.signal)
        if (controller.signal.aborted) return
        setGateStatus(status)
        if (lab.operatorToken && status.armed && status.sessionId === sessionID) {
          synchronizePendingDecisions(await gateClient.pending(controller.signal))
        } else {
          synchronizePendingDecisions([])
        }
        setControlConnection('ready')
        first = false
      } catch (error) {
        if (controller.signal.aborted) return
        setControlConnection('error')
        setControlError(error instanceof Error ? error.message : 'Lab gate control status is unavailable.')
      }
    }
    void reconcile()
    const interval = window.setInterval(() => void reconcile(), 3_000)
    return () => { controller.abort(); window.clearInterval(interval) }
  }, [activeSession, demo, gateClient, lab.operatorToken, sessionID])

  useEffect(() => {
    if (lab.pendingDecisions.size === 0) return
    const interval = window.setInterval(() => setNowMs(Date.now()), 100)
    return () => window.clearInterval(interval)
  }, [lab.pendingDecisions.size])

  const ephemeralEdgeMs = Array.from(lab.ephemeralEvents.values())
    .reduce((latest, event) => Math.max(latest, event.occurredAtMs), 0)
  const effectiveLiveEdgeMs = demo
    ? demoPipelineEnvelope.serverNowMs
    : Math.max(liveEdgeMs, ephemeralEdgeMs, epochMs)
  const allEvents = useMemo(() => {
    return mergeLiveEvents(recordedEvents, lab.ephemeralEvents.values(), effectiveLiveEdgeMs)
  }, [effectiveLiveEdgeMs, lab.ephemeralEvents, recordedEvents])
  const visualEvents = useMemo(() => allEvents.filter((event) => event.kind !== 'health'), [allEvents])
  const filteredEvents = useMemo(() => selectFilteredEvents(lab, visualEvents), [lab, visualEvents])
  const projectedLastMs = filteredEvents.reduce((latest, event) => Math.max(latest, event.occurredAtMs + 2_000), epochMs + 10_000)
  const durationInFrames = Math.max(1, Math.ceil(((Math.max(projectedLastMs, effectiveLiveEdgeMs) - epochMs) / 1000) * FPS))
  const qualityCursorMs = cursorMs >= epochMs ? cursorMs : effectiveLiveEdgeMs
  const usesLiveStream = !demo && activeSession && lab.mode !== 'replay'
  const captureStatus = latestCaptureStatus(gateway.data.flowActivityStatuses, sessionID)
  const activityQuality = useMemo(() => deriveActivityDataQuality({
    cursorMs: qualityCursorMs,
    windows: activity.windows,
    status: captureStatus,
    healthEvents: allEvents.filter((event) => event.kind === 'health'),
    streamDropped: demo ? 0 : lab.traceDropped,
    traceConnection: demo ? 'idle' : lab.traceConnection,
    usesLiveStream,
    atLiveEdge: activeSession && (playback === 'following' || Math.abs(qualityCursorMs - effectiveLiveEdgeMs) <= 1_000),
  }), [activeSession, activity.windows, allEvents, captureStatus, demo, effectiveLiveEdgeMs, lab.traceConnection, lab.traceDropped, playback, qualityCursorMs, usesLiveStream])
  const inputProps = useMemo(() => ({
    epochMs,
    fps: FPS,
    events: filteredEvents,
    mode: lab.mode,
    selectedEventId: lab.selectedEventId,
    selectedTraceId: lab.selectedTraceId,
  }), [epochMs, filteredEvents, lab.mode, lab.selectedEventId, lab.selectedTraceId])

  const sessionKnown = demo || gateway.data.sessions.some((session) => session.id === sessionID)
  const stillLoading = !demo && gateway.connectionState === 'loading' && gateway.data.sessions.length === 0
  if (!sessionID) return <StatePage title="Missing session ID" detail="Open Proxy Lab from the experiment index." />
  if (stillLoading) return <StatePage title="Loading session" detail="Preparing the durable timeline and shared clock…" />
  if (!sessionKnown) return <StatePage title="Session not found" detail={`No session named ${sessionID} exists. The route was not replaced with another session.`} />

  const historical = playback !== 'following' && cursorMs < effectiveLiveEdgeMs - 1_000
  const candidateClients = Array.from(new Set([
    ...visualEvents.map((event) => event.summary.clientIp),
    ...gateway.data.flows.map((flow) => flow.client_ip),
    ...gateway.data.dnsQueries.map((query) => query.client_ip),
    ...gateway.data.activityEpisodes.map((episode) => episode.client_ip),
  ].filter((client): client is string => Boolean(client)))).sort()
  const refreshGate = async () => {
    const status = await gateClient.status()
    setGateStatus(status)
    if (lab.operatorToken && status.armed) synchronizePendingDecisions(await gateClient.pending())
    else synchronizePendingDecisions([])
    setControlConnection('ready')
    setControlError(null)
  }
  const runStatusCommand = async (key: string, command: () => Promise<NonNullable<typeof lab.gateStatus>>) => {
    setControlInFlight(key, true)
    setControlError(null)
    try {
      setGateStatus(await command())
      await refreshGate()
    } catch (error) {
      if (error instanceof GateAPIError && error.status === 409) await refreshGate().catch(() => undefined)
      setControlError(error instanceof Error ? error.message : 'Lab gate command failed.')
    } finally {
      setControlInFlight(key, false)
    }
  }
  const decide = async (decisionId: string, verdict: 'accept' | 'drop') => {
    const key = `decision:${decisionId}`
    setControlInFlight(key, true)
    setControlError(null)
    try {
      const response = await gateClient.decide(decisionId, verdict)
      completeGateDecision(response.result)
      synchronizePendingDecisions(await gateClient.pending())
      setGateStatus(await gateClient.status())
    } catch (error) {
      if (error instanceof GateAPIError && error.status === 409) await refreshGate().catch(() => undefined)
      setControlError(error instanceof Error ? error.message : 'Decision failed.')
    } finally {
      setControlInFlight(key, false)
    }
  }
  return (
    <main className="min-h-screen overflow-x-hidden bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/95">
        <div className="mx-auto flex max-w-[1900px] flex-wrap items-center gap-4 px-5 py-4">
          <div className="grid h-10 w-10 place-items-center border border-cyan-700 bg-cyan-950 text-cyan-300"><Network size={20} /></div>
          <div className="min-w-0 flex-1">
            <p className="text-[10px] font-bold uppercase tracking-[0.2em] text-cyan-400">Debug experiment</p>
            <h1 className="truncate text-xl font-semibold">Proxy Lab · {demo ? 'deterministic fixture' : gateway.data.selectedSession?.name || sessionID}</h1>
          </div>
          <div className="flex w-full flex-wrap items-center gap-3 text-xs text-slate-400 sm:w-auto">
            <StatusDot label="PocketBase" value={demo ? 'demo' : gateway.connectionState} />
            <StatusDot label="Trace" value={demo ? 'fixture' : lab.traceConnection} />
            <button aria-label="Refresh session" className="grid h-9 w-9 place-items-center border border-slate-700 hover:border-slate-500" onClick={() => void gateway.refresh()} type="button"><RefreshCw size={15} /></button>
            <Link className="inline-flex items-center gap-2 border border-slate-700 px-3 py-2 hover:border-slate-500" to="/"><ArrowLeft size={14} /> Experiments</Link>
          </div>
        </div>
      </header>

      <div className="mx-auto max-w-[1900px] space-y-4 px-5 py-5">
        {demo ? <div className="border border-amber-800 bg-amber-950/30 px-4 py-2 text-xs text-amber-200">Deterministic demo · {demoPipelineEnvelope.events.length} source events · capture loss is marked on the quality timeline</div> : null}
        {!demo && gateway.timeline.manifest?.gateAuditComplete === false ? <div className="border border-rose-800 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">Recorded gate audit is incomplete · {gateway.timeline.manifest.gateAuditDrops ?? 0} audit item(s) were lost. Missing intervals must not be interpreted as normal forwarding.</div> : null}
        {(!demo && (gateway.error || activity.error || lab.traceError)) || lab.controlError ? (
          <div className="border border-rose-800 bg-rose-950/40 px-4 py-3 text-sm text-rose-200">{lab.controlError || (!demo && (lab.traceError || activity.error || gateway.error))}</div>
        ) : null}
        <div className="grid grid-cols-1 gap-4 xl:grid-cols-[minmax(0,1fr)_360px]">
          <div className="min-w-0 space-y-3">
            <PipelinePlayer
              durationInFrames={durationInFrames}
              inputProps={inputProps}
              liveEdgeMs={effectiveLiveEdgeMs}
              playback={demo && playback === 'following' ? 'paused' : playback}
              quality={activityQuality}
              rate={rate}
              reduceMotion={reduceMotion}
            />
            <PipelineFilters events={visualEvents} filters={lab.filters} onChange={setProxyLabFilters} />
          </div>
          <aside className="space-y-3">
            <ModeSwitcher mode={lab.mode} onChange={setProxyLabMode} />
            <GateHealth
              busy={(key) => lab.controlInFlight.has(key)}
              controlStatus={demo ? 'fixture' : lab.controlConnection}
              streamDropped={demo ? 0 : lab.traceDropped}
              onDisarm={() => void runStatusCommand('disarm', () => gateClient.disarm())}
              onDrain={() => void runStatusCommand('drain', () => gateClient.drain())}
              onPause={() => void runStatusCommand('pause', () => gateClient.pause())}
              onResume={() => void runStatusCommand('resume', () => gateClient.resume())}
              status={lab.gateStatus}
              traceStatus={demo ? 'fixture' : lab.traceConnection}
            />
            <GateArmDialog
              busy={lab.controlInFlight.has('arm')}
              candidateClients={candidateClients}
              mode={lab.mode}
              onArm={(clientIps, mode, strict) => void runStatusCommand('arm', () => gateClient.arm({ sessionId: sessionID, mode, clientIps, strict }))}
              onToken={setOperatorToken}
              sessionId={sessionID}
              status={lab.gateStatus}
              token={lab.operatorToken}
            />
            <QueueInspector
              actionable={lab.controlConnection === 'ready' && Boolean(lab.operatorToken)}
              decisions={Array.from(lab.pendingDecisions.values())}
              events={visualEvents}
              gateMode={lab.gateStatus?.mode ?? null}
              historical={historical && (lab.mode === 'turn-based' || lab.mode === 'strict' || lab.mode === 'dns')}
              inFlight={lab.controlInFlight}
              nowMs={nowMs}
              onApprove={(id) => void decide(id, 'accept')}
              onAcceptNext={(count) => void runStatusCommand('accept-next', () => gateClient.acceptNext(count))}
              onApproveAll={() => {
                const count = lab.pendingDecisions.size
                void runStatusCommand('approve-all', async () => {
                  const response = await gateClient.approveAll(count)
                  response.results.forEach(completeGateDecision)
                  return response.status
                })
              }}
              onReject={(id) => void decide(id, 'drop')}
              recent={lab.recentDecisions}
              onSelect={selectProxyLabEvent}
            />
            <p aria-live="polite" className="sr-only">{lab.announcement}</p>
            <EventInspector events={visualEvents} selectedEventId={lab.selectedEventId} selectedTraceId={lab.selectedTraceId} />
          </aside>
        </div>
      </div>
    </main>
  )
}

function EventInspector({ events, selectedEventId, selectedTraceId }: {
  events: PipelineEvent[]
  selectedEventId: string | null
  selectedTraceId: string | null
}) {
  const selected = events.find((event) => event.id === selectedEventId || event.traceId === selectedTraceId)
  return (
    <section className="border border-slate-800 bg-slate-900/70 p-3">
      <h2 className="text-sm font-semibold">Transition inspector</h2>
      {!selected ? <p className="mt-2 text-xs text-slate-500">Select a queued flow or transition to inspect timing provenance.</p> : (
        <div className="mt-2 space-y-2 text-xs">
          <span className={`inline-block border px-2 py-1 font-bold ${selected.timing === 'derived' ? 'border-violet-700 text-violet-300' : 'border-emerald-700 text-emerald-300'}`}>{selected.timing === 'derived' ? 'DERIVED TIMING' : 'OBSERVED'}</span>
          <p className="font-mono text-slate-300">{selected.kind} / {selected.stage}</p>
          <p className="break-all font-mono text-slate-500">{selected.summary.flowKey || selected.traceId}</p>
          {selected.kind === 'route' ? <p className="text-amber-300">Gateway approximation, not a client packet path.</p> : null}
        </div>
      )}
    </section>
  )
}

function StatePage({ title, detail }: { title: string; detail: string }) {
  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 px-5 text-slate-100">
      <section className="w-full max-w-xl border border-slate-800 bg-slate-900 p-7">
        <h1 className="text-2xl font-semibold">{title}</h1><p className="mt-3 text-sm text-slate-400">{detail}</p>
        <Link className="mt-6 inline-flex items-center gap-2 text-sm font-semibold text-cyan-300" to="/"><ArrowLeft size={15} /> Back to experiments</Link>
      </section>
    </main>
  )
}

function StatusDot({ label, value }: { label: string; value: string }) {
  return <span className="inline-flex items-center gap-1.5"><span aria-hidden className="h-2 w-2 rounded-full bg-cyan-400" />{label}: <strong className="font-mono text-slate-200">{value}</strong></span>
}

function usePrefersReducedMotion() {
  const [reduced, setReduced] = useState(false)
  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReduced(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])
  return reduced
}

function pocketBaseURL() {
  const configured = import.meta.env.VITE_POCKETBASE_URL
  return (configured || `${window.location.protocol}//${window.location.hostname}:8090`).replace(/\/$/, '')
}

function latestCaptureStatus<T extends { session: string; reported_at: string }>(statuses: readonly T[], sessionID: string) {
  return statuses
    .filter((status) => status.session === sessionID)
    .sort((left, right) => Date.parse(right.reported_at) - Date.parse(left.reported_at))[0] ?? null
}
