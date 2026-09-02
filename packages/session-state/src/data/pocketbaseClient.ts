import type {
  DNSQuery,
  Destination,
  ActivityEpisode,
  Flow,
  FlowAssociation,
  FlowActivityChunk,
  FlowActivityStatus,
  FlowActivityWindow,
  FlowAttribution,
  GatewayData,
  Route,
  Session,
  SessionManifest,
  SessionWindow,
  TimelineLOD,
} from './types'

const defaultUrl = typeof window === 'undefined'
  ? 'http://127.0.0.1:8090'
  : `${window.location.protocol}//${window.location.hostname}:8090`

const baseUrl = (import.meta.env.VITE_POCKETBASE_URL ?? defaultUrl).replace(
  /\/$/,
  ''
)

type ListResponse<T> = {
  items: T[]
  page: number
  totalPages: number
}

export type RealtimeEvent<T> = {
  action: string
  record: T
}

export type ClearGatewayDataResult = {
  deleted: Record<string, number>
  skipped: string[]
}

type RealtimeCallback<T> = (event: RealtimeEvent<T>) => void

export const pb = {
  collection(name: string) {
    return {
      subscribe<T>(topic: string, callback: RealtimeCallback<T>) {
        return realtime.subscribe(name, topic, callback)
      },
    }
  },
}

export async function getGatewayData(
  sessionId?: string | null
): Promise<GatewayData> {
  const sessions = await listAllRecords<Session>('sessions', {
    sort: '-created',
  })
  const selectedSession = selectSession(sessions, sessionId)
  const sessionFilter = selectedSession
    ? `session="${selectedSession.id}"`
    : undefined
  const [flows, dnsQueries, attributions, activityEpisodes, flowAssociations, flowActivityStatuses, destinations, routes] =
    await Promise.all([
      listAllRecords<Flow>('flows', {
        sort: '-last_seen',
        filter: sessionFilter,
      }),
      listAllRecords<DNSQuery>('dns_queries', {
        sort: '-timestamp',
        filter: sessionFilter,
      }),
      listAllRecords<FlowAttribution>('flow_attributions', {
        sort: '-observed_at',
        filter: sessionFilter,
      }),
      listAllRecords<ActivityEpisode>('activity_episodes', {
        sort: 'start',
        filter: sessionFilter,
      }),
      listAllRecords<FlowAssociation>('flow_associations', {
        sort: 'observed_at',
        filter: sessionFilter,
      }),
      listAllRecords<FlowActivityStatus>('flow_activity_status', {
        sort: '-reported_at',
        filter: sessionFilter,
      }),
      listAllRecords<Destination>('destinations', {
        sort: '-last_seen',
      }),
      listAllRecords<Route>('routes', {
        sort: '-completed_at',
        filter: sessionFilter,
      }),
    ])

  return {
    sessions,
    selectedSession,
    flows,
    dnsQueries,
    attributions,
    activityEpisodes,
    flowAssociations,
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses,
    destinations,
    routes,
  }
}

export async function getSessions(signal?: AbortSignal) {
  return listAllRecords<Session>('sessions', { sort: '-created', signal })
}

export async function getSessionManifest(sessionId: string, signal?: AbortSignal) {
  try {
    const manifest = await requestJSON<SessionManifest>(
      `/api/infrareveal/sessions/${encodeURIComponent(sessionId)}/manifest`,
      signal,
    )
    return { ...manifest, transport: 'timeline' as const }
  } catch (error) {
    if (!isNotFound(error)) throw error
    const session = (await getSessions(signal)).find((candidate) => candidate.id === sessionId)
    if (!session) throw error
    return createCollectionSessionManifest(session)
  }
}

export async function getSessionWindow({
  sessionId,
  fromMs,
  toMs,
  lod,
  flowIds = [],
  signal,
}: {
  sessionId: string
  fromMs: number
  toMs: number
  lod: TimelineLOD
  flowIds?: string[]
  signal?: AbortSignal
}) {
  try {
    return await getTimelineSessionWindow({ sessionId, fromMs, toMs, lod, flowIds, signal })
  } catch (error) {
    if (!isNotFound(error)) throw error
    return getCollectionSessionWindow({ sessionId, fromMs, toMs, lod, flowIds, signal })
  }
}

async function getTimelineSessionWindow({
  sessionId,
  fromMs,
  toMs,
  lod,
  flowIds,
  signal,
}: {
  sessionId: string
  fromMs: number
  toMs: number
  lod: TimelineLOD
  flowIds: string[]
  signal?: AbortSignal
}) {
  const merged = emptySessionWindow(fromMs, toMs, lod)
  let cursor: string | null = null
  do {
    const params = new URLSearchParams({
      from: String(Math.round(fromMs)),
      to: String(Math.round(toMs)),
      lod,
      limit: '1000',
    })
    if (flowIds.length > 0) params.set('flow', flowIds.join(','))
    if (cursor) params.set('cursor', cursor)
    const page = await requestJSON<SessionWindow>(
      `/api/infrareveal/sessions/${encodeURIComponent(sessionId)}/window?${params.toString()}`,
      signal,
    )
    mergeSessionWindow(merged, page)
    cursor = page.nextCursor
  } while (cursor)
  merged.nextCursor = null
  return merged
}

/** Compatibility path for gateways running the collection API but not timeline routes yet. */
export async function getCollectionSessionWindow({
  sessionId,
  fromMs,
  toMs,
  lod,
  flowIds = [],
  signal,
}: {
  sessionId: string
  fromMs: number
  toMs: number
  lod: TimelineLOD
  flowIds?: string[]
  signal?: AbortSignal
}): Promise<SessionWindow> {
  const sessionFilter = `session="${escapeFilterValue(sessionId)}"`
  const from = formatPocketBaseDate(fromMs)
  const to = formatPocketBaseDate(toMs)
  const overview = lod === 'overview'
  const flowFilter = joinFilters(
    sessionFilter,
    `start < "${to}"`,
    `last_seen >= "${from}"`,
    valueFilter('id', flowIds),
  )
  const [flows, activityEpisodes, flowActivityStatuses, dnsQueries, flowActivityChunks, flowActivityWindows] = await Promise.all([
    listAllRecords<Flow>('flows', { sort: 'start', filter: flowFilter, signal }),
    listOptionalRecords<ActivityEpisode>('activity_episodes', {
      sort: 'start',
      filter: joinFilters(sessionFilter, `start < "${to}"`, `last_seen >= "${from}"`),
      signal,
    }),
    listOptionalRecords<FlowActivityStatus>('flow_activity_status', {
      sort: '-reported_at',
      filter: sessionFilter,
      signal,
    }),
    overview
      ? Promise.resolve([] as DNSQuery[])
      : listOptionalRecords<DNSQuery>('dns_queries', {
          sort: 'timestamp',
          filter: joinFilters(
            sessionFilter,
            `timestamp >= "${formatPocketBaseDate(fromMs - 5 * 60_000)}"`,
            `timestamp < "${to}"`,
          ),
          signal,
        }),
    overview
      ? Promise.resolve([] as FlowActivityChunk[])
      : listOptionalRecords<FlowActivityChunk>('flow_activity_chunks', {
          sort: 'chunk_start',
          filter: joinFilters(
            sessionFilter,
            `chunk_start >= "${formatPocketBaseDate(fromMs - 10_000)}"`,
            `chunk_start < "${to}"`,
            valueFilter('flow', flowIds),
          ),
          signal,
        }),
    overview
      ? Promise.resolve([] as FlowActivityWindow[])
      : listOptionalRecords<FlowActivityWindow>('flow_activity_windows', {
          sort: 'window_start',
          filter: joinFilters(
            sessionFilter,
            `window_start >= "${formatPocketBaseDate(fromMs - 60_000)}"`,
            `window_start < "${to}"`,
          ),
          signal,
        }),
  ])

  const visibleFlowIDs = flows.map((flow) => flow.id)
  const destinationIPs = Array.from(new Set(flows.map((flow) => flow.destination_ip).filter(Boolean)))
  const [attributions, flowAssociations, destinations, routes] = await Promise.all([
    listRelatedRecords<FlowAttribution>('flow_attributions', sessionFilter, 'flow', visibleFlowIDs, 'observed_at', signal),
    listRelatedRecords<FlowAssociation>('flow_associations', sessionFilter, 'flow', visibleFlowIDs, 'observed_at', signal),
    listRelatedRecords<Destination>('destinations', '', 'ip', destinationIPs, 'ip', signal),
    listRelatedRecords<Route>('routes', sessionFilter, 'destination_ip', destinationIPs, 'completed_at', signal),
  ])

  return {
    range: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
    lod,
    watermark: new Date().toISOString(),
    flows,
    dnsQueries,
    attributions,
    activityEpisodes,
    flowAssociations,
    flowActivityChunks,
    flowActivityWindows,
    flowActivityStatuses,
    destinations,
    routes,
    nextCursor: null,
  }
}

export function createCollectionSessionManifest(session: Session): SessionManifest {
  const serverNow = new Date().toISOString()
  const startedAt = session.started_at || session.created
  const endedAt = session.active ? null : session.ended_at || session.updated
  const edge = endedAt || serverNow
  return {
    sessionId: session.id,
    name: session.name,
    startedAt,
    endedAt,
    active: session.active,
    serverNow,
    watermark: session.updated || edge,
    counts: {},
    coverage: { from: startedAt, to: edge },
    transport: 'collections',
  }
}

function emptySessionWindow(fromMs: number, toMs: number, lod: TimelineLOD): SessionWindow {
  return {
    range: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
    lod,
    watermark: '',
    flows: [],
    dnsQueries: [],
    attributions: [],
    activityEpisodes: [],
    flowAssociations: [],
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: [],
    destinations: [],
    routes: [],
    nextCursor: null,
  }
}

function mergeSessionWindow(target: SessionWindow, page: SessionWindow) {
  target.range = page.range
  target.lod = page.lod
  target.watermark = page.watermark
  target.flows = mergeById(target.flows, page.flows)
  target.dnsQueries = mergeById(target.dnsQueries, page.dnsQueries)
  target.attributions = mergeById(target.attributions, page.attributions)
  target.activityEpisodes = mergeById(target.activityEpisodes, page.activityEpisodes)
  target.flowAssociations = mergeById(target.flowAssociations, page.flowAssociations)
  target.flowActivityChunks = mergeById(target.flowActivityChunks, page.flowActivityChunks)
  target.flowActivityWindows = mergeById(target.flowActivityWindows, page.flowActivityWindows)
  target.flowActivityStatuses = mergeById(target.flowActivityStatuses, page.flowActivityStatuses)
  target.destinations = mergeById(target.destinations, page.destinations)
  target.routes = mergeById(target.routes, page.routes)
}

function mergeById<T extends { id: string }>(current: T[], incoming: T[]) {
  const byId = new Map(current.map((record) => [record.id, record]))
  for (const record of incoming) byId.set(record.id, record)
  return Array.from(byId.values())
}

async function requestJSON<T>(path: string, signal?: AbortSignal) {
  const response = await fetch(`${baseUrl}${path}`, { signal })
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string; message?: string } | null
    throw new PocketBaseRequestError(
      response.status,
      payload?.error || payload?.message || `PocketBase request failed: ${response.status} ${response.statusText}`,
    )
  }
  return response.json() as Promise<T>
}

class PocketBaseRequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'PocketBaseRequestError'
  }
}

function isNotFound(error: unknown): error is PocketBaseRequestError {
  return error instanceof PocketBaseRequestError && error.status === 404
}

export function emptyGatewayData(): GatewayData {
  return {
    sessions: [],
    selectedSession: null,
    flows: [],
    dnsQueries: [],
    attributions: [],
    activityEpisodes: [],
    flowAssociations: [],
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: [],
    destinations: [],
    routes: [],
  }
}

export async function getFlowActivityRange(
  sessionId: string,
  startMs: number,
  endMs: number,
  flowIds: string[] = [],
) {
  if (!sessionId || !Number.isFinite(startMs) || !Number.isFinite(endMs) || endMs <= startMs) {
    return { chunks: [] as FlowActivityChunk[], windows: [] as FlowActivityWindow[] }
  }
  const start = formatPocketBaseDate(startMs)
  const overlapStart = formatPocketBaseDate(startMs - 60_000)
  const end = formatPocketBaseDate(endMs)
  const sessionFilter = `session="${sessionId}"`
  const rangeFilter = `${sessionFilter} && chunk_start >= "${start}" && chunk_start < "${end}"`
  const flowBatches = flowIds.length > 0 ? chunk(flowIds, 40) : [[]]
  const [chunkPages, windows] = await Promise.all([
    Promise.all(flowBatches.map((batch) => {
      const flowFilter = batch.length > 0
        ? ` && (${batch.map((flowId) => `flow="${escapeFilterValue(flowId)}"`).join(' || ')})`
        : ''
      return listAllRecords<FlowActivityChunk>('flow_activity_chunks', {
        sort: 'chunk_start',
        filter: `${rangeFilter}${flowFilter}`,
      })
    })),
    listAllRecords<FlowActivityWindow>('flow_activity_windows', {
      sort: 'window_start',
      filter: `${sessionFilter} && window_start >= "${overlapStart}" && window_start < "${end}"`,
    }),
  ])
  const chunks = Array.from(
    new Map(chunkPages.flat().map((activityChunk) => [activityChunk.id, activityChunk])).values(),
  ).sort((left, right) => Date.parse(left.chunk_start) - Date.parse(right.chunk_start))
  return { chunks, windows }
}

function chunk<T>(values: T[], size: number) {
  const batches: T[][] = []
  for (let index = 0; index < values.length; index += size) {
    batches.push(values.slice(index, index + size))
  }
  return batches
}

function escapeFilterValue(value: string) {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"')
}

export function formatPocketBaseDate(milliseconds: number) {
  return new Date(milliseconds).toISOString().replace('T', ' ')
}

export async function clearGatewayData(): Promise<ClearGatewayDataResult> {
  const response = await fetch(`${baseUrl}/api/infrareveal/clear-observations`, {
    method: 'POST',
  })
  if (!response.ok) {
    const message = await response.text()
    throw new Error(message || `Clear request failed: ${response.status} ${response.statusText}`)
  }

  return response.json() as Promise<ClearGatewayDataResult>
}

async function listAllRecords<T>(
  collection: string,
  options: {
    filter?: string
    sort?: string
    signal?: AbortSignal
  },
) {
  const result: T[] = []
  let page = 1
  while (true) {
    const params = new URLSearchParams({ page: String(page), perPage: '500' })
    if (options.sort) params.set('sort', options.sort)
    if (options.filter) params.set('filter', options.filter)
    const response = await fetch(`${baseUrl}/api/collections/${collection}/records?${params.toString()}`, {
      signal: options.signal,
    })
    if (!response.ok) {
      throw new PocketBaseRequestError(
        response.status,
        `PocketBase request failed: ${response.status} ${response.statusText}`,
      )
    }
    const payload = (await response.json()) as ListResponse<T>
    result.push(...(payload.items ?? []))
    const totalPages = Math.max(1, payload.totalPages || 1)
    if (page >= totalPages) break
    page += 1
  }
  return result
}

async function listOptionalRecords<T>(
  collection: string,
  options: { filter?: string; sort?: string; signal?: AbortSignal },
) {
  try {
    return await listAllRecords<T>(collection, options)
  } catch (error) {
    if (isNotFound(error)) return []
    throw error
  }
}

async function listRelatedRecords<T extends { id: string }>(
  collection: string,
  baseFilter: string,
  field: string,
  values: string[],
  sort: string,
  signal?: AbortSignal,
) {
  if (values.length === 0) return [] as T[]
  const pages = await Promise.all(chunk(Array.from(new Set(values)), 40).map((batch) =>
    listOptionalRecords<T>(collection, {
      filter: joinFilters(baseFilter, valueFilter(field, batch)),
      sort,
      signal,
    }),
  ))
  return mergeById([], pages.flat())
}

function joinFilters(...filters: Array<string | undefined>) {
  return filters.filter(Boolean).join(' && ')
}

function valueFilter(field: string, values: string[]) {
  if (values.length === 0) return undefined
  return `(${values.map((value) => `${field}="${escapeFilterValue(value)}"`).join(' || ')})`
}

function selectSession(sessions: Session[], sessionId?: string | null) {
  if (sessionId) {
    return sessions.find((session) => session.id === sessionId) ?? null
  }
  return sessions.find((session) => session.active) ?? sessions[0] ?? null
}

class RealtimeClient {
  private clientId = ''
  private connectPromise: Promise<void> | null = null
  private eventSource: EventSource | null = null
  private subscriptions = new Map<
    string,
    Map<RealtimeCallback<unknown>, EventListener>
  >()

  async subscribe<T>(
    collection: string,
    topic: string,
    callback: RealtimeCallback<T>
  ) {
    const subscription = `${collection}/${topic}`
    const listener: EventListener = (event) => {
      const message = event as MessageEvent<string>
      try {
        callback(JSON.parse(message.data) as RealtimeEvent<T>)
      } catch {
        callback({ action: 'error', record: {} as T })
      }
    }

    const listeners = this.subscriptions.get(subscription) ?? new Map()
    listeners.set(callback as RealtimeCallback<unknown>, listener)
    this.subscriptions.set(subscription, listeners)

    try {
      await this.connect()
      this.eventSource?.addEventListener(subscription, listener)
      await this.submitSubscriptions()
    } catch (error) {
      this.eventSource?.removeEventListener(subscription, listener)
      this.removeSubscription(subscription, callback as RealtimeCallback<unknown>)
      if (this.subscriptions.size === 0) this.disconnect()
      throw error
    }

    return async () => {
      this.eventSource?.removeEventListener(subscription, listener)
      this.removeSubscription(subscription, callback as RealtimeCallback<unknown>)
      await this.submitSubscriptions().catch(() => undefined)
      if (this.subscriptions.size === 0) {
        this.disconnect()
      }
    }
  }

  private async connect() {
    if (this.clientId && this.eventSource) {
      return
    }

    this.connectPromise ??= new Promise((resolve, reject) => {
      const source = new EventSource(`${baseUrl}/api/realtime`)
      const timeout = window.setTimeout(() => {
        source.close()
        this.eventSource = null
        this.connectPromise = null
        reject(new Error('Realtime connection timed out.'))
      }, 15000)

      source.onerror = () => {
        window.clearTimeout(timeout)
        source.close()
        this.eventSource = null
        this.clientId = ''
        this.connectPromise = null
        this.notifyError()
        reject(new Error('Realtime connection failed.'))
      }

      source.addEventListener('PB_CONNECT', (event) => {
        window.clearTimeout(timeout)
        const message = event as MessageEvent<string>
        this.clientId = message.lastEventId
        this.eventSource = source
        this.connectPromise = null
        this.attachListeners()
        resolve()
      })
    })

    return this.connectPromise
  }

  private attachListeners() {
    if (!this.eventSource) {
      return
    }
    for (const [subscription, listeners] of this.subscriptions) {
      for (const listener of listeners.values()) {
        this.eventSource.addEventListener(subscription, listener)
      }
    }
  }

  private async submitSubscriptions() {
    if (!this.clientId) {
      return
    }

    const response = await fetch(`${baseUrl}/api/realtime`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        clientId: this.clientId,
        subscriptions: Array.from(this.subscriptions.keys()),
      }),
    })
    if (!response.ok) {
      throw new Error(`PocketBase realtime subscription failed: ${response.status} ${response.statusText}`)
    }
  }

  private removeSubscription(subscription: string, callback: RealtimeCallback<unknown>) {
    const current = this.subscriptions.get(subscription)
    current?.delete(callback)
    if (current?.size === 0) this.subscriptions.delete(subscription)
  }

  private notifyError() {
    for (const listeners of this.subscriptions.values()) {
      for (const callback of listeners.keys()) {
        callback({ action: 'error', record: {} })
      }
    }
  }

  private disconnect() {
    this.eventSource?.close()
    this.eventSource = null
    this.clientId = ''
    this.connectPromise = null
  }
}

const realtime = new RealtimeClient()
