import {
  createCollectionSessionManifest,
  getCollectionSessionWindow,
  getSessionManifest,
  getSessions,
  getSessionWindow,
  pb,
} from '../../data/pocketbaseClient'
import type {
  ConnectionState,
  Session,
  SessionWindow,
  TimelineLOD,
} from '../../data/types'
import { parseEpoch, windowSegments } from '../domain/time'
import {
  applyRealtimeBatch,
  applySessionWindow,
  clearDetailPages,
  hasDetailPage,
  isRealtimeRecordInWorkingSet,
  resetSessionTimeline,
  reconcileOverviewWindow,
  sessionTimelineStore,
  setDetailPageLoading,
  setTimelineConnection,
  setTimelineManifest,
  setTimelineSessions,
  tickTimelineClock,
  touchDetailPages,
} from '../store/sessionStore'
import type { QueuedRealtimeEvent } from '../store/sessionStore'

type RealtimeEvent<T> = { action: string; record: T }
type PendingPage = { controller: AbortController; promise: Promise<void> }

const subscriptions = [
  ['sessions', 'sessions'],
  ['flows', 'flows'],
  ['dns_queries', 'dnsQueries'],
  ['flow_attributions', 'attributions'],
  ['activity_episodes', 'activityEpisodes'],
  ['flow_associations', 'flowAssociations'],
  ['flow_activity_chunks', 'flowActivityChunks'],
  ['flow_activity_windows', 'flowActivityWindows'],
  ['flow_activity_status', 'flowActivityStatuses'],
  ['destinations', 'destinations'],
  ['routes', 'routes'],
  ['gate_events', 'gateEvents'],
] as const

/** Owns bootstrap, realtime delivery, reconciliation, and bounded detail loading. */
class SessionController {
  private generation = 0
  private requestedSessionId: string | null = null
  private unsubscribers: Array<() => void> = []
  private reconcileTimer = 0
  private clockTimer = 0
  private batchTimer = 0
  private buffering = false
  private queue = new Map<string, QueuedRealtimeEvent>()
  private pendingPages = new Map<string, PendingPage>()
  private startPromise: Promise<void> | null = null
  private collectionTransport = false

  start(requestedSessionId: string | null) {
    if (this.startPromise && this.requestedSessionId === requestedSessionId) return this.startPromise
    this.requestedSessionId = requestedSessionId
    const generation = ++this.generation
    this.stopRuntime()
    this.collectionTransport = false
    this.queue.clear()
    this.buffering = false
    this.startPromise = this.bootstrap(generation, requestedSessionId).finally(() => {
      if (generation === this.generation) this.startPromise = null
    })
    return this.startPromise
  }

  refresh() {
    this.startPromise = null
    return this.start(this.requestedSessionId)
  }

  async ensureDetailRange(fromMs: number, toMs: number, flowIds: string[] = [], lod: TimelineLOD = chooseLOD(fromMs, toMs)) {
    const state = sessionTimelineStore.getState()
    const sessionId = state.selectedSessionId
    if (!sessionId || toMs <= fromMs) return
    const normalizedFlowIDs = Array.from(new Set(flowIds)).sort()
    const flowKey = hashFlowIDs(normalizedFlowIDs)
    const pageDescriptors = windowSegments(fromMs, toMs).map((segment) => ({
      ...segment,
      key: `${sessionId}:${segment.fromMs}:${lod}:${flowKey}`,
    }))
    const activeKeys = new Set(pageDescriptors.map((page) => page.key))
    for (const [key, pending] of this.pendingPages) {
      if (!activeKeys.has(key)) pending.controller.abort()
    }
    touchDetailPages(pageDescriptors.map((page) => page.key))

    const loads = pageDescriptors.map((page) => {
      if (hasDetailPage(page.key)) return Promise.resolve()
      const pending = this.pendingPages.get(page.key)
      if (pending) return pending.promise
      const controller = new AbortController()
      setDetailPageLoading(page.key, true)
      const request = this.loadDetailPage(sessionId, page, normalizedFlowIDs, lod, controller.signal)
        .finally(() => {
          this.pendingPages.delete(page.key)
          setDetailPageLoading(page.key, false)
        })
      this.pendingPages.set(page.key, { controller, promise: request })
      return request
    })
    await Promise.all(loads)
  }

  clearDetail() {
    clearDetailPages()
  }

  dispose() {
    this.generation += 1
    this.stopRuntime()
    this.queue.clear()
    this.buffering = false
    this.startPromise = null
  }

  private async bootstrap(generation: number, requestedSessionId: string | null) {
    setTimelineConnection('loading')
    try {
      const sessions = await getSessions()
      if (generation !== this.generation) return
      const selected = selectSession(sessions, requestedSessionId)
      resetSessionTimeline(selected?.id ?? null, sessions)
      if (!selected) {
        setTimelineConnection('error', 'No gateway session is available.')
        return
      }

      this.buffering = true
      const subscribed = await this.openSubscriptions(generation)
      if (generation !== this.generation) return
      const manifest = selected.started_at
        ? await getSessionManifest(selected.id)
        : createCollectionSessionManifest(selected)
      if (generation !== this.generation) return
      this.collectionTransport = manifest.transport === 'collections'
      setTimelineManifest(manifest)
      const fromMs = parseEpoch(manifest.coverage.from, parseEpoch(manifest.startedAt))
      const toMs = Math.max(fromMs + 1, parseEpoch(manifest.coverage.to, parseEpoch(manifest.serverNow)))
      const overview = await this.getWindow({
        sessionId: selected.id,
        fromMs,
        toMs,
        lod: 'overview',
      })
      if (generation !== this.generation) return
      applySessionWindow(overview)
      this.buffering = false
      this.flushQueue()
      setTimelineConnection(subscribed ? 'live' : 'polling')
      this.startTimers(generation)
    } catch (error) {
      if (generation !== this.generation) return
      this.buffering = false
      this.flushQueue()
      setTimelineConnection('error', normalizeError(error))
      this.startTimers(generation)
    }
  }

  private async openSubscriptions(generation: number) {
    const opened: Array<() => void> = []
    try {
      for (const [collectionName, storeCollection] of subscriptions) {
        const unsubscribe = await pb.collection(collectionName).subscribe('*', (event: RealtimeEvent<Record<string, unknown>>) => {
          if (generation !== this.generation) return
          if (event.action === 'error') {
            this.handleRealtimeFailure(generation)
            return
          }
          const record = event.record as Record<string, unknown> & {
            id: string
            session?: string
            updated?: string
            created?: string
            flow?: string
            chunk_start?: string
            window_start?: string
            timestamp?: string
            queued_at?: string
            ip?: string
          }
          if (!record.id) return
          if (!isRealtimeRecordInWorkingSet(storeCollection, record)) return
          this.enqueue({ collection: storeCollection, action: event.action, record })
          if (collectionName === 'sessions') window.setTimeout(() => this.reconcile(generation, true), 0)
        })
        opened.push(unsubscribe)
      }
      if (generation !== this.generation) {
        for (const stop of opened) stop()
        return false
      }
      this.unsubscribers.push(...opened)
      return true
    } catch {
      for (const stop of opened) stop()
      return false
    }
  }

  private enqueue(event: QueuedRealtimeEvent) {
    this.queue.set(`${event.collection}/${event.record.id}`, event)
    if (this.buffering || this.batchTimer) return
    this.batchTimer = window.setTimeout(() => {
      this.batchTimer = 0
      this.flushQueue()
    }, 50)
  }

  private flushQueue() {
    if (this.buffering || this.queue.size === 0) return
    const events = Array.from(this.queue.values())
    this.queue.clear()
    applyRealtimeBatch(events)
  }

  private startTimers(generation: number) {
    this.stopTimers()
    this.clockTimer = window.setInterval(tickTimelineClock, 1000)
    this.reconcileTimer = window.setInterval(() => this.reconcile(generation, false), 10_000)
  }

  private async reconcile(generation: number, full: boolean) {
    const state = sessionTimelineStore.getState()
    const sessionId = state.selectedSessionId
    if (!sessionId || generation !== this.generation) return
    try {
      const sessions = await getSessions()
      if (generation !== this.generation) return
      const selected = sessions.find((session) => session.id === sessionId)
      if (!selected) throw new Error('The selected session no longer exists.')
      const manifest = this.collectionTransport
        ? createCollectionSessionManifest(selected)
        : await getSessionManifest(sessionId)
      this.collectionTransport = manifest.transport === 'collections'
      if (generation !== this.generation) return
      setTimelineSessions(sessions)
      setTimelineManifest(manifest)
      const epochMs = parseEpoch(manifest.startedAt)
      const edgeMs = manifest.active ? parseEpoch(manifest.serverNow) : parseEpoch(manifest.endedAt, parseEpoch(manifest.coverage.to))
      const repairingConnection = this.unsubscribers.length === 0
      const fromMs = full || repairingConnection ? epochMs : Math.max(epochMs, edgeMs - 2 * 60_000)
      const overview = await this.getWindow({
        sessionId,
        fromMs,
        toMs: Math.max(fromMs + 1, edgeMs),
        lod: 'overview',
      })
      if (generation !== this.generation) return
      reconcileOverviewWindow(overview)
      if (this.unsubscribers.length === 0) {
        const subscribed = await this.openSubscriptions(generation)
        setTimelineConnection(subscribed ? 'live' : 'polling')
      } else {
        setTimelineConnection('live')
      }
    } catch (error) {
      if (generation !== this.generation) return
      const nextState: ConnectionState = navigator.onLine ? 'polling' : 'offline'
      setTimelineConnection(nextState, normalizeError(error))
    }
  }

  private async loadDetailPage(
    sessionId: string,
    page: { key: string; fromMs: number; toMs: number },
    flowIds: string[],
    lod: TimelineLOD,
    signal: AbortSignal,
  ) {
    const batches = flowIds.length > 0 ? chunk(flowIds, 200) : [[]]
    let merged: SessionWindow | null = null
    for (const batch of batches) {
      const window = await this.getWindow({
        sessionId,
        fromMs: page.fromMs,
        toMs: page.toMs,
        lod,
        flowIds: batch,
        signal,
      })
      merged = merged ? mergeWindows(merged, window) : window
    }
    if (!merged || sessionTimelineStore.getState().selectedSessionId !== sessionId) return
    applySessionWindow(merged, {
      key: page.key,
      fromMs: page.fromMs,
      toMs: page.toMs,
      lod,
      flowKey: hashFlowIDs(flowIds),
      flowIds: new Set(flowIds),
    })
  }

  private stopRuntime() {
    this.stopTimers()
    if (this.batchTimer) window.clearTimeout(this.batchTimer)
    this.batchTimer = 0
    for (const unsubscribe of this.unsubscribers.splice(0)) void unsubscribe()
    for (const pending of this.pendingPages.values()) pending.controller.abort()
    this.pendingPages.clear()
  }

  private getWindow(options: Parameters<typeof getSessionWindow>[0]) {
    return this.collectionTransport
      ? getCollectionSessionWindow(options)
      : getSessionWindow(options)
  }

  private handleRealtimeFailure(generation: number) {
    if (generation !== this.generation || this.unsubscribers.length === 0) return
    for (const unsubscribe of this.unsubscribers.splice(0)) void unsubscribe()
    setTimelineConnection(navigator.onLine ? 'polling' : 'offline', 'Realtime disconnected; cached playback remains available while the timeline reconciles.')
  }

  private stopTimers() {
    if (this.reconcileTimer) window.clearInterval(this.reconcileTimer)
    if (this.clockTimer) window.clearInterval(this.clockTimer)
    this.reconcileTimer = 0
    this.clockTimer = 0
  }
}

export const sessionController = new SessionController()

export function chooseLOD(fromMs: number, toMs: number): TimelineLOD {
  const span = toMs - fromMs
  if (span <= 60_000) return '50ms'
  if (span <= 5 * 60_000) return '500ms'
  return '5s'
}

function selectSession(sessions: Session[], requestedSessionId: string | null) {
  if (requestedSessionId) return sessions.find((session) => session.id === requestedSessionId) ?? null
  return sessions.find((session) => session.active) ?? sessions[0] ?? null
}

function hashFlowIDs(flowIds: string[]) {
  if (flowIds.length === 0) return 'all'
  let hash = 2166136261
  for (const value of flowIds) {
    for (let index = 0; index < value.length; index += 1) {
      hash ^= value.charCodeAt(index)
      hash = Math.imul(hash, 16777619)
    }
  }
  return `${flowIds.length}-${(hash >>> 0).toString(36)}`
}

function chunk<T>(values: T[], size: number) {
  const result: T[][] = []
  for (let index = 0; index < values.length; index += size) result.push(values.slice(index, index + size))
  return result
}

function mergeWindows(target: SessionWindow, incoming: SessionWindow) {
  const result = { ...target }
  result.flows = mergeById(target.flows, incoming.flows)
  result.dnsQueries = mergeById(target.dnsQueries, incoming.dnsQueries)
  result.attributions = mergeById(target.attributions, incoming.attributions)
  result.activityEpisodes = mergeById(target.activityEpisodes, incoming.activityEpisodes)
  result.flowAssociations = mergeById(target.flowAssociations, incoming.flowAssociations)
  result.flowActivityChunks = mergeById(target.flowActivityChunks, incoming.flowActivityChunks)
  result.flowActivityWindows = mergeById(target.flowActivityWindows, incoming.flowActivityWindows)
  result.flowActivityStatuses = mergeById(target.flowActivityStatuses, incoming.flowActivityStatuses)
  result.destinations = mergeById(target.destinations, incoming.destinations)
  result.routes = mergeById(target.routes, incoming.routes)
  result.watermark = incoming.watermark || target.watermark
  return result
}

function mergeById<T extends { id: string }>(left: T[], right: T[]) {
  const records = new Map(left.map((record) => [record.id, record]))
  for (const record of right) records.set(record.id, record)
  return Array.from(records.values())
}

function normalizeError(error: unknown) {
  if (error instanceof DOMException && error.name === 'AbortError') return 'The timeline request was cancelled.'
  return error instanceof Error && error.message ? error.message : 'PocketBase is unavailable; showing cached data.'
}
