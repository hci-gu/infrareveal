import { compareRouteRevisions, routeAvailableAt, routeBindingKey, routeMatchesFlow } from '../../data/routeEvidence'
import { createStore } from 'zustand/vanilla'
import type {
  ActivityEpisode,
  ConnectionState,
  DNSQuery,
  Destination,
  Flow,
  FlowActivityChunk,
  FlowActivityStatus,
  FlowActivityWindow,
  FlowAssociation,
  FlowAttribution,
  GatewayData,
  GateEvent,
  Route,
  Session,
  SessionManifest,
  SessionWindow,
  TimelineLOD,
} from '../../data/types'
import { emptyGatewayData } from '../../data/pocketbaseClient'
import { retentionWindowMs, parseEpoch } from '../domain/time'
import { TemporalBucketIndex } from './temporalIndex'

/** Default raw-detail working-set budget shared by both dashboards. */
export const DEFAULT_DETAIL_CACHE_BUDGET_BYTES = 48 * 1024 * 1024

type RecordBase = { id: string; created?: string; updated?: string; session?: string }

type EntityMaps = {
  sessions: Map<string, Session>
  flows: Map<string, Flow>
  dnsQueries: Map<string, DNSQuery>
  attributions: Map<string, FlowAttribution>
  activityEpisodes: Map<string, ActivityEpisode>
  flowAssociations: Map<string, FlowAssociation>
  flowActivityChunks: Map<string, FlowActivityChunk>
  flowActivityWindows: Map<string, FlowActivityWindow>
  flowActivityStatuses: Map<string, FlowActivityStatus>
  destinations: Map<string, Destination>
  routes: Map<string, Route>
  gateEvents: Map<string, GateEvent>
}

type EntityOwnership = {
  routes: Set<string>
  dnsQueries: Set<string>
  flowActivityChunks: Set<string>
  flowActivityWindows: Set<string>
  gateEvents: Set<string>
}

type EntityReferenceCounts = {
  [Collection in keyof EntityOwnership]: Map<string, number>
}

export type DetailPage = {
  key: string
  fromMs: number
  toMs: number
  lod: TimelineLOD
  flowKey: string
  flowIds: Set<string>
  bytes: number
  lastAccessed: number
  ownership: EntityOwnership
}

type SessionIndexes = {
  flows: TemporalBucketIndex
  episodes: TemporalBucketIndex
  dns: TemporalBucketIndex
  chunks: TemporalBucketIndex
  windows: TemporalBucketIndex
  gates: TemporalBucketIndex
}

export type PlaybackState = 'following' | 'playing' | 'paused' | 'buffering'
export type TimelineUIState = {
  viewMode: 'timeline' | 'treemap'
  zoomFrames: number | 'all'
  selectedClipId: string | null
  selectedServiceId: string | null
  focusedServiceId: string | null
  collapsedServiceIds: string[]
  inspectorOpen: boolean
}

export type SessionTimelineState = {
  sessions: Map<string, Session>
  selectedSessionId: string | null
  manifest: SessionManifest | null
  entities: EntityMaps
  indexes: SessionIndexes
  pages: Map<string, DetailPage>
  detailRefCounts: EntityReferenceCounts
  tombstones: Map<string, number>
  loadingPageKeys: Set<string>
  cacheBytes: number
  detailCacheBudgetBytes: number
  overviewReady: boolean
  connectionState: ConnectionState
  error: string | null
  mode: 'live' | 'recorded'
  playback: PlaybackState
  rate: number
  cursorMs: number
  liveEdgeMs: number
  viewport: { fromMs: number; toMs: number }
  serverClock: { serverNowMs: number; syncedAtMs: number }
  watermark: string | null
  ui: TimelineUIState
  sessionVersion: number
  overviewVersion: number
  detailVersion: number
  clockVersion: number
  uiVersion: number
}

export type QueuedRealtimeEvent = {
  collection: keyof EntityMaps
  action: string
  record: RecordBase
}

function createEntities(): EntityMaps {
  return {
    sessions: new Map(),
    flows: new Map(),
    dnsQueries: new Map(),
    attributions: new Map(),
    activityEpisodes: new Map(),
    flowAssociations: new Map(),
    flowActivityChunks: new Map(),
    flowActivityWindows: new Map(),
    flowActivityStatuses: new Map(),
    destinations: new Map(),
    routes: new Map(),
    gateEvents: new Map(),
  }
}

function createIndexes(): SessionIndexes {
  return {
    flows: new TemporalBucketIndex(),
    episodes: new TemporalBucketIndex(),
    dns: new TemporalBucketIndex(),
    chunks: new TemporalBucketIndex(),
    windows: new TemporalBucketIndex(),
    gates: new TemporalBucketIndex(),
  }
}

function createDetailRefCounts(): EntityReferenceCounts {
  return {
    routes: new Map(),
    dnsQueries: new Map(),
    flowActivityChunks: new Map(),
    flowActivityWindows: new Map(),
    gateEvents: new Map(),
  }
}

const initialState = (): SessionTimelineState => ({
  sessions: new Map(),
  selectedSessionId: null,
  manifest: null,
  entities: createEntities(),
  indexes: createIndexes(),
  pages: new Map(),
  detailRefCounts: createDetailRefCounts(),
  tombstones: new Map(),
  loadingPageKeys: new Set(),
  cacheBytes: 0,
  detailCacheBudgetBytes: DEFAULT_DETAIL_CACHE_BUDGET_BYTES,
  overviewReady: false,
  connectionState: 'loading',
  error: null,
  mode: 'recorded',
  playback: 'paused',
  rate: 1,
  cursorMs: 0,
  liveEdgeMs: 0,
  viewport: { fromMs: 0, toMs: 0 },
  serverClock: { serverNowMs: 0, syncedAtMs: 0 },
  watermark: null,
  ui: {
    viewMode: 'timeline',
    zoomFrames: 'all',
    selectedClipId: null,
    selectedServiceId: null,
    focusedServiceId: null,
    collapsedServiceIds: [],
    inspectorOpen: false,
  },
  sessionVersion: 0,
  overviewVersion: 0,
  detailVersion: 0,
  clockVersion: 0,
  uiVersion: 0,
})

export const sessionTimelineStore = createStore<SessionTimelineState>()(() => initialState())

export function resetSessionTimeline(selectedSessionId: string | null, sessions: Session[]) {
  const next = initialState()
  next.sessions = new Map(sessions.map((session) => [session.id, session]))
  next.entities.sessions = next.sessions
  next.selectedSessionId = selectedSessionId
  next.sessionVersion = sessionTimelineStore.getState().sessionVersion + 1
  sessionTimelineStore.setState(next, true)
}

export function setTimelineSessions(sessions: Session[]) {
  const state = sessionTimelineStore.getState()
  const nextSessions = new Map(sessions.map((session) => [session.id, session]))
  if (mapsHaveSameRevisions(state.sessions, nextSessions)) return
  state.entities.sessions = nextSessions
  sessionTimelineStore.setState({
    sessions: nextSessions,
    entities: state.entities,
    sessionVersion: state.sessionVersion + 1,
  })
}

export function setTimelineManifest(manifest: SessionManifest) {
  const state = sessionTimelineStore.getState()
  const epochMs = manifest.ephemeral ? Math.max(parseEpoch(manifest.startedAt), parseEpoch(manifest.serverNow) - retentionWindowMs(manifest.retentionMinutes)) : parseEpoch(manifest.startedAt, parseEpoch(manifest.coverage.from, Date.now()))
  const serverNowMs = parseEpoch(manifest.serverNow, Date.now())
  const endedAtMs = parseEpoch(manifest.endedAt, 0)
  const liveEdgeMs = manifest.active ? serverNowMs : Math.max(epochMs, endedAtMs)
  const firstManifest = state.manifest === null
  const cursorMs = firstManifest
    ? (manifest.active ? liveEdgeMs : epochMs)
    : Math.min(Math.max(epochMs, state.cursorMs), liveEdgeMs)
  sessionTimelineStore.setState({
    manifest,
    mode: manifest.active ? 'live' : 'recorded',
    playback: firstManifest ? (manifest.active ? 'following' : 'paused') : state.playback,
    cursorMs,
    liveEdgeMs,
    viewport: firstManifest ? { fromMs: Math.max(epochMs, cursorMs - 60_000), toMs: liveEdgeMs } : state.viewport,
    serverClock: { serverNowMs, syncedAtMs: performanceNow() },
    watermark: manifest.watermark,
    ui: firstManifest
      ? { ...state.ui, zoomFrames: manifest.active ? 30 * 60 : 'all' }
      : state.ui,
    clockVersion: state.clockVersion + 1,
  })
  pruneEphemeralTimeline()
}

export function tickTimelineClock() {
  const state = sessionTimelineStore.getState()
  if (!state.manifest?.active || state.connectionState === 'offline' || state.connectionState === 'error' || state.error) return
  const projected = state.serverClock.serverNowMs + Math.max(0, performanceNow() - state.serverClock.syncedAtMs)
  if (projected <= state.liveEdgeMs) return
  sessionTimelineStore.setState({ liveEdgeMs: projected, clockVersion: state.clockVersion + 1 })
  pruneEphemeralTimeline()
}

/** Advances the shared edge from an accepted ephemeral trace without allowing
 * a future-dated source event to outrun the gateway's reported server time. */
export function observeTimelineLiveEdge(occurredAtMs: number, serverNowMs: number) {
  if (!Number.isFinite(occurredAtMs) || !Number.isFinite(serverNowMs)) return
  const state = sessionTimelineStore.getState()
  const candidate = Math.max(0, Math.min(occurredAtMs, serverNowMs))
  const nextEdge = Math.max(state.liveEdgeMs, candidate)
  const nextServerNow = Math.max(state.serverClock.serverNowMs, serverNowMs)
  if (nextEdge === state.liveEdgeMs && nextServerNow === state.serverClock.serverNowMs) return
  sessionTimelineStore.setState({
    liveEdgeMs: nextEdge,
    serverClock: { serverNowMs: nextServerNow, syncedAtMs: performanceNow() },
    clockVersion: state.clockVersion + 1,
  })
}

export function setTimelinePlayback(update: Partial<Pick<SessionTimelineState, 'playback' | 'rate' | 'cursorMs' | 'viewport'>>) {
  const state = sessionTimelineStore.getState()
  sessionTimelineStore.setState({ ...update, clockVersion: state.clockVersion + 1 })
}

export function setTimelineUI(update: Partial<TimelineUIState>) {
  const state = sessionTimelineStore.getState()
  sessionTimelineStore.setState({
    ui: { ...state.ui, ...update },
    uiVersion: state.uiVersion + 1,
  })
}

export function toggleTimelineServiceCollapsed(serviceId: string) {
  const state = sessionTimelineStore.getState()
  const collapsedServiceIds = state.ui.collapsedServiceIds.includes(serviceId)
    ? state.ui.collapsedServiceIds.filter((id) => id !== serviceId)
    : [...state.ui.collapsedServiceIds, serviceId]
  setTimelineUI({ collapsedServiceIds })
}

export function setTimelineConnection(connectionState: ConnectionState, error: string | null = null) {
  sessionTimelineStore.setState({ connectionState, error })
}

export function applySessionWindow(
  window: SessionWindow,
  page?: Omit<DetailPage, 'bytes' | 'lastAccessed' | 'ownership'>,
  forceOverviewChange = false,
) {
  const state = sessionTimelineStore.getState()
  if (page) {
    const previous = state.pages.get(page.key)
    if (previous) removePage(state, previous)
  }
  const changes = mergeWindowEntities(state, window)

  if (page) {
    const ownership: EntityOwnership = {
      routes: new Set(window.routes.map(record => record.id)),
      dnsQueries: new Set(window.dnsQueries.map((record) => record.id)),
      flowActivityChunks: new Set(window.flowActivityChunks.map((record) => record.id)),
      flowActivityWindows: new Set(window.flowActivityWindows.map((record) => record.id)),
      gateEvents: new Set(window.gateEvents.map((record) => record.id)),
    }
    const bytes = estimateWindowBytes(window)
    state.pages.set(page.key, { ...page, bytes, ownership, lastAccessed: Date.now() })
    addOwnershipReferences(state, ownership)
    state.cacheBytes += bytes
    evictDetailPages(state, new Set([page.key]))
  }

  pruneRouteRevisions(state)
  const overview = window.lod === 'overview'
  const overviewChanged = forceOverviewChange || changes.overview || (overview && !state.overviewReady)
  const detailChanged = changes.detail || Boolean(page)
  sessionTimelineStore.setState({
    pages: state.pages,
    detailRefCounts: state.detailRefCounts,
    cacheBytes: state.cacheBytes,
    overviewReady: state.overviewReady || overview,
    watermark: window.watermark || state.watermark,
    overviewVersion: state.overviewVersion + (overviewChanged ? 1 : 0),
    detailVersion: state.detailVersion + (detailChanged ? 1 : 0),
  })
  pruneEphemeralTimeline()
}

/** Replaces the authoritative overview portion of a range, repairing missed SSE deletes. */
export function reconcileOverviewWindow(window: SessionWindow) {
  const state = sessionTimelineStore.getState()
  const fromMs = parseEpoch(window.range.from)
  const toMs = parseEpoch(window.range.to)
  let removed = removeIndexedRecordsMissingFromWindow(state, 'flows', state.indexes.flows.query(fromMs, toMs), new Set(window.flows.map((record) => record.id)))
  removed = removeIndexedRecordsMissingFromWindow(state, 'activityEpisodes', state.indexes.episodes.query(fromMs, toMs), new Set(window.activityEpisodes.map((record) => record.id))) || removed

  const visibleFlowIDs = new Set(window.flows.map((record) => record.id))
  removed = removeMissingRelations(state, 'attributions', visibleFlowIDs, new Set(window.attributions.map((record) => record.id))) || removed
  removed = removeMissingRelations(state, 'flowAssociations', visibleFlowIDs, new Set(window.flowAssociations.map((record) => record.id))) || removed
  applySessionWindow(window, undefined, removed)
}

export function touchDetailPages(keys: string[]) {
  const state = sessionTimelineStore.getState()
  const now = Date.now()
  for (const key of keys) {
    const page = state.pages.get(key)
    if (page) page.lastAccessed = now
  }
}

export function setDetailPageLoading(key: string, loading: boolean) {
  const state = sessionTimelineStore.getState()
  if (loading) state.loadingPageKeys.add(key)
  else state.loadingPageKeys.delete(key)
  sessionTimelineStore.setState({
    loadingPageKeys: state.loadingPageKeys,
    detailVersion: state.detailVersion + 1,
  })
}

export function clearDetailPages() {
  const state = sessionTimelineStore.getState()
  for (const page of Array.from(state.pages.values())) removePage(state, page)
  state.pages.clear()
  for (const counts of Object.values(state.detailRefCounts)) counts.clear()
  state.cacheBytes = 0
  sessionTimelineStore.setState({
    pages: state.pages,
    detailRefCounts: state.detailRefCounts,
    cacheBytes: 0,
    detailVersion: state.detailVersion + 1,
  })
}

export function configureDetailCacheBudget(bytes: number) {
  const state = sessionTimelineStore.getState()
  const detailCacheBudgetBytes = Math.max(1, Math.floor(bytes))
  state.detailCacheBudgetBytes = detailCacheBudgetBytes
  evictDetailPages(state, new Set())
  sessionTimelineStore.setState({
    detailCacheBudgetBytes,
    pages: state.pages,
    cacheBytes: state.cacheBytes,
    detailVersion: state.detailVersion + 1,
  })
}

export function applyRealtimeBatch(events: QueuedRealtimeEvent[]) {
  const state = sessionTimelineStore.getState()
  let overviewChanged = false
  let detailChanged = false
  let sessionsChanged = false
  const touchedPages = new Set<string>()
  for (const event of events) {
    const record = event.record
    if (event.collection !== 'sessions' && event.collection !== 'destinations' && record.session && record.session !== state.selectedSessionId) {
      continue
    }
    const changed = event.action === 'delete'
      ? applyDeleteTombstone(state, event.collection, record)
      : upsertEntity(state, event.collection, record)
    if (!changed) continue
    if (event.collection === 'sessions') sessionsChanged = true
    else if (event.collection === 'flowActivityChunks' || event.collection === 'flowActivityWindows' || event.collection === 'dnsQueries' || event.collection === 'gateEvents') {
      detailChanged = true
      if (event.action !== 'delete') attachRealtimeDetailOwnership(state, event.collection, record, touchedPages)
    } else {
      overviewChanged = true
      if (event.collection === 'routes') { attachRealtimeDetailOwnership(state, 'routes', record, touchedPages); detailChanged = true }
      if (event.collection === 'flows') detailChanged = true
    }
  }
  pruneRouteRevisions(state)
  evictDetailPages(state, touchedPages)
  sessionTimelineStore.setState({
    sessions: state.sessions,
    pages: state.pages,
    detailRefCounts: state.detailRefCounts,
    cacheBytes: state.cacheBytes,
    tombstones: state.tombstones,
    sessionVersion: state.sessionVersion + (sessionsChanged ? 1 : 0),
    overviewVersion: state.overviewVersion + (overviewChanged ? 1 : 0),
    detailVersion: state.detailVersion + (detailChanged ? 1 : 0),
  })
  pruneEphemeralTimeline()
}

export function selectOverviewGatewayData(state = sessionTimelineStore.getState()): GatewayData {
  const selectedSession = state.selectedSessionId ? state.sessions.get(state.selectedSessionId) ?? null : null
  return {
    sessions: Array.from(state.sessions.values()).sort(sortSessions),
    selectedSession,
    flows: Array.from(state.entities.flows.values()),
    dnsQueries: [],
    attributions: Array.from(state.entities.attributions.values()),
    activityEpisodes: Array.from(state.entities.activityEpisodes.values()),
    flowAssociations: Array.from(state.entities.flowAssociations.values()),
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: Array.from(state.entities.flowActivityStatuses.values()),
    destinations: Array.from(state.entities.destinations.values()),
    routes: Array.from(state.entities.routes.values()),
    gateEvents: [],
  }
}

export function selectDetailGatewayData(fromMs: number, toMs: number, flowIds?: string[], state = sessionTimelineStore.getState()): GatewayData {
  const data = selectOverviewGatewayData(state)
  const requested = flowIds?.length ? new Set(flowIds) : null
  const chunkIDs = state.indexes.chunks.query(fromMs, toMs)
  const windowIDs = state.indexes.windows.query(fromMs, toMs)
  const dnsIDs = state.indexes.dns.query(fromMs - 5 * 60_000, toMs)
  const gateIDs = state.indexes.gates.query(fromMs, toMs)
  data.flowActivityChunks = Array.from(chunkIDs)
    .map((id) => state.entities.flowActivityChunks.get(id))
    .filter((record): record is FlowActivityChunk => record !== undefined)
    .filter((record) => !requested || requested.has(record.flow))
  data.flowActivityWindows = Array.from(windowIDs)
    .map((id) => state.entities.flowActivityWindows.get(id))
    .filter((record): record is FlowActivityWindow => record !== undefined)
  data.dnsQueries = Array.from(dnsIDs)
    .map((id) => state.entities.dnsQueries.get(id))
    .filter((record): record is DNSQuery => record !== undefined)
  data.gateEvents = Array.from(gateIDs)
    .map((id) => state.entities.gateEvents.get(id))
    .filter((record): record is GateEvent => record !== undefined)
  return data
}

export function hasDetailPage(key: string) {
  return sessionTimelineStore.getState().pages.has(key)
}

export function isRealtimeRecordInWorkingSet(
  collection: keyof EntityMaps,
  record: { flow?: string; ip?: string; chunk_start?: string; window_start?: string; timestamp?: string; queued_at?: string },
) {
  if (collection === 'destinations') return Boolean(record.ip)
  if (collection !== 'flowActivityChunks' && collection !== 'flowActivityWindows' && collection !== 'dnsQueries' && collection !== 'gateEvents') return true
  const state = sessionTimelineStore.getState()
  const at = collection === 'flowActivityChunks'
    ? parseEpoch(record.chunk_start)
    : collection === 'flowActivityWindows'
      ? parseEpoch(record.window_start)
      : collection === 'dnsQueries'
        ? parseEpoch(record.timestamp)
        : parseEpoch(record.queued_at)
  if (!at) return false
  return Array.from(state.pages.values()).some((page) => {
    const from = collection === 'dnsQueries' ? page.fromMs - 5 * 60_000 : collection === 'gateEvents' ? page.fromMs : page.fromMs - 60_000
    const flowAccepted = collection !== 'flowActivityChunks' || page.flowIds.size === 0 || (record.flow ? page.flowIds.has(record.flow) : false)
    return flowAccepted && at >= from && at < page.toMs
  })
}

function mergeWindowEntities(state: SessionTimelineState, window: SessionWindow) {
  let overview = false
  let detail = false
  for (const record of window.flows) overview = upsertEntity(state, 'flows', record) || overview
  for (const record of window.dnsQueries) detail = upsertEntity(state, 'dnsQueries', record) || detail
  for (const record of window.attributions) overview = upsertEntity(state, 'attributions', record) || overview
  for (const record of window.activityEpisodes) overview = upsertEntity(state, 'activityEpisodes', record) || overview
  for (const record of window.flowAssociations) overview = upsertEntity(state, 'flowAssociations', record) || overview
  for (const record of window.flowActivityChunks) detail = upsertEntity(state, 'flowActivityChunks', record) || detail
  for (const record of window.flowActivityWindows) detail = upsertEntity(state, 'flowActivityWindows', record) || detail
  for (const record of window.flowActivityStatuses) overview = upsertEntity(state, 'flowActivityStatuses', record) || overview
  for (const record of window.destinations) overview = upsertEntity(state, 'destinations', record) || overview
  for (const record of window.routes) overview = upsertEntity(state, 'routes', record) || overview
  for (const record of window.gateEvents) detail = upsertEntity(state, 'gateEvents', record) || detail
  return { overview, detail }
}

function removeIndexedRecordsMissingFromWindow(
  state: SessionTimelineState,
  collection: 'flows' | 'activityEpisodes',
  indexedIDs: Set<string>,
  receivedIDs: Set<string>,
) {
  let removed = false
  for (const id of indexedIDs) {
    if (!receivedIDs.has(id)) removed = removeEntity(state, collection, id) || removed
  }
  return removed
}

function removeMissingRelations(
  state: SessionTimelineState,
  collection: 'attributions' | 'flowAssociations',
  visibleFlowIDs: Set<string>,
  receivedIDs: Set<string>,
) {
  const records = state.entities[collection]
  let removed = false
  for (const record of records.values()) {
    if (visibleFlowIDs.has(record.flow) && !receivedIDs.has(record.id)) removed = removeEntity(state, collection, record.id) || removed
  }
  return removed
}

function upsertEntity(state: SessionTimelineState, collection: keyof EntityMaps, incoming: RecordBase) {
  if (state.manifest?.ephemeral) {
    const cutoff = timelineStartMs(state)
    if (collection === 'flows' && parseEpoch((incoming as Flow).last_seen) < cutoff) return false
    if (collection === 'activityEpisodes' && parseEpoch((incoming as ActivityEpisode).last_seen) < cutoff) return false
  }
  const map = state.entities[collection] as Map<string, RecordBase>
  const existing = map.get(incoming.id)
  if (collection === 'routes' && existing) {
    // A realtime row or an older window must not erase separately loaded events.
    const events = [...((existing as Route).evidence_updates ?? []), ...((incoming as Route).evidence_updates ?? [])]
    incoming = {...incoming, evidence_updates: [...new Map(events.map(event => [JSON.stringify(event), event])).values()]} as Route
  }
  const incomingRevision = entityRevision(collection, incoming)
  const tombstoneKey = entityKey(collection, incoming.id)
  const tombstoneRevision = state.tombstones.get(tombstoneKey)
  if (tombstoneRevision !== undefined && tombstoneRevision >= incomingRevision) return false
  if (existing) {
    const existingRevision = entityRevision(collection, existing)
    if (existingRevision > incomingRevision) return false
    if (existingRevision === incomingRevision && JSON.stringify(existing) === JSON.stringify(incoming)) return false
  }
  if (tombstoneRevision !== undefined) state.tombstones.delete(tombstoneKey)
  map.set(incoming.id, incoming)
  indexEntity(state, collection, incoming)
  if (collection === 'sessions') state.sessions.set(incoming.id, incoming as Session)
  return true
}

function applyDeleteTombstone(state: SessionTimelineState, collection: keyof EntityMaps, record: RecordBase) {
  const key = entityKey(collection, record.id)
  const incomingRevision = entityRevision(collection, record)
  const previousTombstone = state.tombstones.get(key)
  const current = (state.entities[collection] as Map<string, RecordBase>).get(record.id)
  const currentRevision = current ? entityRevision(collection, current) : 0
  if (incomingRevision > 0 && currentRevision > incomingRevision) return false
  const deletedAt = Math.max(incomingRevision, currentRevision)
  if (previousTombstone !== undefined && previousTombstone >= deletedAt) return false
  state.tombstones.set(key, deletedAt)
  return removeEntity(state, collection, record.id)
}

function removeEntity(state: SessionTimelineState, collection: keyof EntityMaps, id: string) {
  const map = state.entities[collection] as Map<string, RecordBase>
  if (!map.has(id)) return false
  map.delete(id)
  if (collection === 'flows') {
    state.indexes.flows.remove(id)
    for (const attribution of state.entities.attributions.values()) {
      if (attribution.flow === id) removeEntity(state, 'attributions', attribution.id)
    }
    for (const association of state.entities.flowAssociations.values()) {
      if (association.flow === id) removeEntity(state, 'flowAssociations', association.id)
    }
    for (const chunk of state.entities.flowActivityChunks.values()) {
      if (chunk.flow === id) removeEntity(state, 'flowActivityChunks', chunk.id)
    }
  }
  if (collection === 'activityEpisodes') state.indexes.episodes.remove(id)
  if (collection === 'dnsQueries') state.indexes.dns.remove(id)
  if (collection === 'flowActivityChunks') state.indexes.chunks.remove(id)
  if (collection === 'flowActivityWindows') state.indexes.windows.remove(id)
  if (collection === 'gateEvents') state.indexes.gates.remove(id)
  if (collection === 'sessions') state.sessions.delete(id)
  return true
}

function indexEntity(state: SessionTimelineState, collection: keyof EntityMaps, record: RecordBase) {
  if (collection === 'flows') {
    const flow = record as Flow
    const start = Math.max(parseEpoch(flow.start || flow.created), state.manifest?.ephemeral ? timelineStartMs(state) : 0)
    state.indexes.flows.upsert(flow.id, start, parseEpoch(flow.last_seen || flow.updated, start))
  } else if (collection === 'activityEpisodes') {
    const episode = record as ActivityEpisode
    const start = Math.max(parseEpoch(episode.start || episode.created), state.manifest?.ephemeral ? timelineStartMs(state) : 0)
    state.indexes.episodes.upsert(episode.id, start, parseEpoch(episode.last_seen || episode.updated, start))
  } else if (collection === 'dnsQueries') {
    const dns = record as DNSQuery
    const at = parseEpoch(dns.timestamp || dns.created)
    state.indexes.dns.upsert(dns.id, at)
  } else if (collection === 'flowActivityChunks') {
    const chunk = record as FlowActivityChunk
    const start = parseEpoch(chunk.chunk_start)
    state.indexes.chunks.upsert(chunk.id, start, start + Math.max(1, chunk.chunk_ms))
  } else if (collection === 'flowActivityWindows') {
    const window = record as FlowActivityWindow
    const start = parseEpoch(window.window_start)
    state.indexes.windows.upsert(window.id, start, start + Math.max(1, window.window_ms))
  } else if (collection === 'gateEvents') {
    const gate = record as GateEvent
    const start = parseEpoch(gate.queued_at || gate.created)
    state.indexes.gates.upsert(gate.id, start, parseEpoch(gate.decided_at, start))
  }
}

function removePage(state: SessionTimelineState, page: DetailPage) {
  state.pages.delete(page.key)
  state.cacheBytes = Math.max(0, state.cacheBytes - page.bytes)
  removeOwnedRecords(state, page.ownership.dnsQueries, 'dnsQueries')
  removeOwnedRecords(state, page.ownership.flowActivityChunks, 'flowActivityChunks')
  removeOwnedRecords(state, page.ownership.flowActivityWindows, 'flowActivityWindows')
  removeOwnedRecords(state, page.ownership.gateEvents, 'gateEvents')
  removeOwnedRecords(state, page.ownership.routes, 'routes')
  pruneRouteRevisions(state)
}

function removeOwnedRecords(state: SessionTimelineState, ids: Set<string>, collection: keyof EntityOwnership) {
  const counts = state.detailRefCounts[collection]
  for (const id of ids) {
    const next = Math.max(0, (counts.get(id) ?? 1) - 1)
    if (next === 0) {
      counts.delete(id)
      if (collection !== 'routes') removeEntity(state, collection, id)
    } else {
      counts.set(id, next)
    }
  }
}

function addOwnershipReferences(state: SessionTimelineState, ownership: EntityOwnership) {
  for (const collection of ['dnsQueries', 'flowActivityChunks', 'flowActivityWindows', 'gateEvents', 'routes'] as const) {
    const counts = state.detailRefCounts[collection]
    for (const id of ownership[collection]) counts.set(id, (counts.get(id) ?? 0) + 1)
  }
}

function attachRealtimeDetailOwnership(
  state: SessionTimelineState,
  collection: keyof EntityOwnership,
  record: RecordBase,
  touchedPages: Set<string>,
) {
  const at = collection === 'routes' ? routeAvailableAt(record as Route) : collection === 'flowActivityChunks'
    ? parseEpoch((record as FlowActivityChunk).chunk_start)
    : collection === 'flowActivityWindows'
      ? parseEpoch((record as FlowActivityWindow).window_start)
      : collection === 'dnsQueries'
        ? parseEpoch((record as DNSQuery).timestamp)
        : parseEpoch((record as GateEvent).queued_at)
  if (!at) return
  for (const page of state.pages.values()) {
    const fromMs = collection === 'dnsQueries' ? page.fromMs - 5 * 60_000 : collection === 'gateEvents' ? page.fromMs : page.fromMs - 60_000
    if (collection === 'routes') {
      const route = record as Route
      if (at >= page.toMs || page.ownership.routes.has(route.id)) continue
      if (page.flowIds.size && ![...page.flowIds].some(id => { const flow = state.entities.flows.get(id); return flow && routeMatchesFlow(route, flow) })) continue
      if (at < page.fromMs) {
        const anchors = [...page.ownership.routes].map(id => state.entities.routes.get(id)).filter((r): r is Route => Boolean(r) && routeBindingKey(r!) === routeBindingKey(route) && routeAvailableAt(r!) < page.fromMs)
        if (anchors.some(r => compareRouteRevisions(r, route) >= 0)) continue
        for (const anchor of anchors) { page.ownership.routes.delete(anchor.id); removeOwnedRecords(state, new Set([anchor.id]), 'routes'); const bytes = estimateRecordBytes(anchor); page.bytes = Math.max(0, page.bytes - bytes); state.cacheBytes = Math.max(0, state.cacheBytes - bytes) }
      }
      page.ownership.routes.add(route.id); state.detailRefCounts.routes.set(route.id, (state.detailRefCounts.routes.get(route.id) ?? 0) + 1)
      const bytes = estimateRecordBytes(record); page.bytes += bytes; state.cacheBytes += bytes; touchedPages.add(page.key); continue
    }
    const flowAccepted = collection !== 'flowActivityChunks' || page.flowIds.size === 0 || page.flowIds.has((record as FlowActivityChunk).flow)
    if (!flowAccepted || at < fromMs || at >= page.toMs || page.ownership[collection].has(record.id)) continue
    page.ownership[collection].add(record.id)
    state.detailRefCounts[collection].set(record.id, (state.detailRefCounts[collection].get(record.id) ?? 0) + 1)
    const bytes = estimateRecordBytes(record)
    page.bytes += bytes
    state.cacheBytes += bytes
    touchedPages.add(page.key)
  }
}

function evictDetailPages(state: SessionTimelineState, keep: Set<string>) {
  if (state.cacheBytes <= state.detailCacheBudgetBytes) return
  const candidates = Array.from(state.pages.values())
    .filter((page) => !keep.has(page.key))
    .sort((left, right) => left.lastAccessed - right.lastAccessed)
  for (const page of candidates) {
    if (state.cacheBytes <= state.detailCacheBudgetBytes) break
    removePage(state, page)
  }
}

function estimateWindowBytes(window: SessionWindow) {
  try {
    return JSON.stringify(window).length * 2
  } catch {
    return 0
  }
}

function estimateRecordBytes(record: RecordBase) {
  try {
    return JSON.stringify(record).length * 2
  } catch {
    return 0
  }
}

function mapsHaveSameRevisions<T extends RecordBase>(left: Map<string, T>, right: Map<string, T>) {
  if (left.size !== right.size) return false
  for (const [id, record] of right) {
    const previous = left.get(id)
    if (!previous) return false
    const previousRevision = revision(previous)
    const nextRevision = revision(record)
    if (previousRevision !== nextRevision) return false
    if (nextRevision === 0 && JSON.stringify(previous) !== JSON.stringify(record)) return false
  }
  return true
}

function entityKey(collection: keyof EntityMaps, id: string) {
  return `${collection}:${id}`
}

function revision(record: RecordBase) {
  return parseEpoch(record.updated || record.created, 0)
}

function entityRevision(collection: keyof EntityMaps, record: RecordBase) {
  const systemRevision = revision(record)
  if (systemRevision > 0) return systemRevision
  switch (collection) {
    case 'flows':
      return parseEpoch((record as Flow).last_seen || (record as Flow).start, 0)
    case 'dnsQueries':
      return parseEpoch((record as DNSQuery).timestamp, 0)
    case 'attributions':
      return parseEpoch((record as FlowAttribution).observed_at, 0)
    case 'activityEpisodes':
      return parseEpoch((record as ActivityEpisode).last_seen || (record as ActivityEpisode).start, 0)
    case 'flowAssociations':
      return parseEpoch((record as FlowAssociation).observed_at, 0)
    case 'flowActivityChunks':
      return parseEpoch((record as FlowActivityChunk).updated_at_source || (record as FlowActivityChunk).chunk_start, 0)
    case 'flowActivityWindows':
      return parseEpoch((record as FlowActivityWindow).window_start, 0)
    case 'flowActivityStatuses':
      return parseEpoch((record as FlowActivityStatus).reported_at, 0)
    case 'destinations':
      return parseEpoch((record as Destination).last_seen, 0)
    case 'routes':
      return routeAvailableAt(record as Route)
    case 'gateEvents':
      return parseEpoch((record as GateEvent).decided_at || (record as GateEvent).queued_at, 0)
    case 'sessions':
      return parseEpoch((record as Session).ended_at || (record as Session).started_at || record.created, 0)
  }
}

function performanceNow() {
  return typeof performance === 'undefined' ? Date.now() : performance.now()
}

function sortSessions(left: Session, right: Session) {
  if (left.active !== right.active) return left.active ? -1 : 1
  return parseEpoch(right.started_at || right.created) - parseEpoch(left.started_at || left.created)
}

export function emptySelectedGatewayData() {
  return emptyGatewayData()
}

function pruneRouteRevisions(state: SessionTimelineState) {
  const ips = new Set([...state.entities.flows.values()].map(flow => flow.destination_ip))
  const orphanDestinations = [...state.entities.destinations.values()].filter(d => !ips.has(d.ip))
  for (const d of orphanDestinations.slice(0, Math.max(0, orphanDestinations.length - 256))) state.entities.destinations.delete(d.id)
  const latest = new Map<string, Route>()
  for (const route of state.entities.routes.values()) {
    const key = routeBindingKey(route), previous = latest.get(key)
    if (!previous || compareRouteRevisions(route, previous) > 0) latest.set(key, route)
  }
  const pins = new Set([...latest.values()].map(route => route.id))
  for (const id of state.entities.routes.keys()) if (!pins.has(id) && !state.detailRefCounts.routes.has(id)) state.entities.routes.delete(id)
}

/** Canonical rolling origin, also between server manifest refreshes. */
export function timelineStartMs(state = sessionTimelineStore.getState()) {
  const start = parseEpoch(state.manifest?.startedAt)
  return state.manifest?.ephemeral ? Math.max(start, state.liveEdgeMs - retentionWindowMs(state.manifest.retentionMinutes)) : start
}

/** Independent of server delete events: reconnects and stale responses cannot
 * make the working set grow with session age. Long-lived flows retain identity. */
export function pruneEphemeralTimeline() {
  const state = sessionTimelineStore.getState()
  if (!state.manifest?.ephemeral) return
  const cutoff = timelineStartMs(state)
  let changed = false
  for (const page of [...state.pages.values()]) {
    if (page.toMs <= cutoff) { removePage(state, page); changed = true }
  }
  const remove = (collection: keyof EntityMaps, id: string) => { changed = removeEntity(state, collection, id) || changed }
  for (const record of state.entities.flows.values()) if (parseEpoch(record.last_seen) < cutoff) remove('flows', record.id)
  for (const record of state.entities.activityEpisodes.values()) if (parseEpoch(record.last_seen) < cutoff) remove('activityEpisodes', record.id)
  for (const record of state.entities.attributions.values()) if (!state.entities.flows.has(record.flow)) remove('attributions', record.id)
  for (const record of state.entities.flowAssociations.values()) if (!state.entities.flows.has(record.flow) || !state.entities.activityEpisodes.has(record.episode)) remove('flowAssociations', record.id)
  for (const record of state.entities.dnsQueries.values()) if (parseEpoch(record.timestamp) < cutoff) remove('dnsQueries', record.id)
  for (const record of state.entities.flowActivityChunks.values()) if (parseEpoch(record.chunk_start) + record.chunk_ms <= cutoff) remove('flowActivityChunks', record.id)
  for (const record of state.entities.flowActivityWindows.values()) if (parseEpoch(record.window_start) + record.window_ms <= cutoff) remove('flowActivityWindows', record.id)
  for (const record of state.entities.gateEvents.values()) if (parseEpoch(record.queued_at) < cutoff) remove('gateEvents', record.id)
  const flows = [...state.entities.flows.values()]
  for (const record of state.entities.routes.values()) if (!flows.some(flow => routeMatchesFlow(record, flow))) remove('routes', record.id)
  for (const record of state.entities.routes.values()) {
    const anchors = new Map<string, NonNullable<Route['evidence_updates']>[number]>()
    const recent = (record.evidence_updates ?? []).filter(event => {
      if (parseEpoch(event.available_at) >= cutoff) return true
      const previous = anchors.get(event.kind)
      if (!previous || parseEpoch(previous.available_at) < parseEpoch(event.available_at)) anchors.set(event.kind, event)
      return false
    })
    const updates = [...anchors.values(), ...recent]
    if (updates.length !== record.evidence_updates?.length) {
      state.entities.routes.set(record.id, { ...record, evidence_updates: updates })
      changed = true
    }
  }
  const ips = new Set(flows.map(flow => flow.destination_ip))
  for (const route of state.entities.routes.values()) for (const hop of route.hops ?? []) ips.add(hop.address)
  for (const record of state.entities.destinations.values()) if (!ips.has(record.ip)) remove('destinations', record.id)
  for (const [key, at] of state.tombstones) if (at < cutoff - 60_000) state.tombstones.delete(key)
  while (state.tombstones.size > 10_000) state.tombstones.delete(state.tombstones.keys().next().value!)
  for (const index of Object.values(state.indexes)) index.pruneBefore(cutoff)
  // Release ownership entries for records removed independently of their page.
  for (const page of state.pages.values()) for (const collection of Object.keys(page.ownership) as Array<keyof EntityOwnership>) {
    for (const id of page.ownership[collection]) if (!state.entities[collection].has(id)) {
      page.ownership[collection].delete(id)
      state.detailRefCounts[collection].delete(id)
    }
  }
  const cursorMs = Math.min(state.liveEdgeMs, Math.max(cutoff, state.cursorMs))
  const viewport = { fromMs: Math.max(cutoff, state.viewport.fromMs), toMs: Math.max(cutoff, state.viewport.toMs) }
  sessionTimelineStore.setState({
    cursorMs, viewport, pages: state.pages, cacheBytes: state.cacheBytes,
    overviewVersion: state.overviewVersion + Number(changed),
    detailVersion: state.detailVersion + Number(changed),
  })
}
