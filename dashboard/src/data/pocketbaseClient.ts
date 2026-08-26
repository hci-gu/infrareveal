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
} from './types'

const defaultUrl = 'http://192.168.10.120:8090'
// typeof window === 'undefined'
//   ? 'http://192.168.10.120:8090'
//   : `${window.location.protocol}//${window.location.hostname}:8090`

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
  const sessions = await listRecords<Session>('sessions', {
    sort: '-created',
  })
  const selectedSession = selectSession(sessions, sessionId)
  const sessionFilter = selectedSession
    ? `session="${selectedSession.id}"`
    : undefined
  const [flows, dnsQueries, attributions, activityEpisodes, flowAssociations, flowActivityStatuses, destinations, routes] =
    await Promise.all([
      listRecords<Flow>('flows', {
        sort: '-last_seen',
        filter: sessionFilter,
      }),
      listRecords<DNSQuery>('dns_queries', {
        sort: '-timestamp',
        filter: sessionFilter,
      }),
      listRecords<FlowAttribution>('flow_attributions', {
        sort: '-observed_at',
        filter: sessionFilter,
      }),
      listRecords<ActivityEpisode>('activity_episodes', {
        sort: 'start',
        filter: sessionFilter,
      }),
      listRecords<FlowAssociation>('flow_associations', {
        sort: 'observed_at',
        filter: sessionFilter,
      }),
      listRecords<FlowActivityStatus>('flow_activity_status', {
        sort: '-reported_at',
        filter: sessionFilter,
      }),
      listRecords<Destination>('destinations', {
        sort: '-last_seen',
      }),
      listRecords<Route>('routes', {
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

async function listRecords<T>(
  collection: string,
  options: {
    filter?: string
    sort?: string
  }
) {
  const params = new URLSearchParams({
    page: '1',
    perPage: '1000',
    skipTotal: '1',
  })

  if (options.sort) {
    params.set('sort', options.sort)
  }
  if (options.filter) {
    params.set('filter', options.filter)
  }

  const response = await fetch(
    `${baseUrl}/api/collections/${collection}/records?${params.toString()}`
  )
  if (!response.ok) {
    throw new Error(
      `PocketBase request failed: ${response.status} ${response.statusText}`
    )
  }

  const payload = (await response.json()) as ListResponse<T>
  return payload.items ?? []
}

async function listAllRecords<T>(
  collection: string,
  options: {
    filter?: string
    sort?: string
  },
) {
  const result: T[] = []
  let page = 1
  while (true) {
    const params = new URLSearchParams({ page: String(page), perPage: '500' })
    if (options.sort) params.set('sort', options.sort)
    if (options.filter) params.set('filter', options.filter)
    const response = await fetch(`${baseUrl}/api/collections/${collection}/records?${params.toString()}`)
    if (!response.ok) {
      throw new Error(`PocketBase request failed: ${response.status} ${response.statusText}`)
    }
    const payload = (await response.json()) as ListResponse<T>
    result.push(...(payload.items ?? []))
    const totalPages = Math.max(1, payload.totalPages || 1)
    if (page >= totalPages) break
    page += 1
  }
  return result
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

    await this.connect()
    this.eventSource?.addEventListener(subscription, listener)
    await this.submitSubscriptions()

    return async () => {
      this.eventSource?.removeEventListener(subscription, listener)
      const current = this.subscriptions.get(subscription)
      current?.delete(callback as RealtimeCallback<unknown>)
      if (current?.size === 0) {
        this.subscriptions.delete(subscription)
      }
      await this.submitSubscriptions()
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
        this.connectPromise = null
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

    await fetch(`${baseUrl}/api/realtime`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        clientId: this.clientId,
        subscriptions: Array.from(this.subscriptions.keys()),
      }),
    })
  }

  private disconnect() {
    this.eventSource?.close()
    this.eventSource = null
    this.clientId = ''
    this.connectPromise = null
  }
}

const realtime = new RealtimeClient()
