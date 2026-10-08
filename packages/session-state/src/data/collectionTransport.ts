import { parseEpoch, retentionWindowMs } from '../timeline/domain/time'
import type {
  DNSQuery,
  Destination,
  ActivityEpisode,
  ActivityChunkSummary,
  Flow,
  FlowAssociation,
  FlowActivityChunk,
  FlowActivityStatus,
  FlowActivityWindow,
  FlowAttribution,
  GateEvent,
  Route,
  Session,
  SessionManifest,
  SessionWindow,
  SessionWindowRequest,
} from './types'

import { isNotFound, requestJSON } from './pocketbaseHttp'
import { attachRouteEvidenceUpdates } from './routeRecords'
import type { RouteEvidenceRecord } from './routeRecords'
import { mergeById } from './sessionData'

type ListResponse<T> = {
  items: T[]
  page: number
  totalPages: number
}

export async function getSessions(signal?: AbortSignal) {
  return listAllRecords<Session>('sessions', { sort: '-created', signal })
}

async function attachRouteUpdates(routes: Route[], filter?: string, signal?: AbortSignal): Promise<Route[]> {
  if (!routes.length) return routes
  const updates = await listOptionalRecords<RouteEvidenceRecord>('route_evidence_updates', { filter, sort: 'available_at', signal })
  return attachRouteEvidenceUpdates(routes, updates)
}

/** Compatibility path for gateways running the collection API but not timeline routes yet. */
export async function getCollectionSessionWindow({
  sessionId,
  fromMs,
  toMs,
  lod,
  flowIds = [],
  signal,
}: SessionWindowRequest): Promise<SessionWindow> {
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
  const [flows, activityEpisodes, flowActivityStatuses, dnsQueries, flowActivityChunks, flowActivityWindows, gateEvents] = await Promise.all([
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
    overview
      ? Promise.resolve([] as GateEvent[])
      : listOptionalRecords<GateEvent>('gate_events', {
          sort: 'queued_at',
          filter: joinFilters(sessionFilter, `queued_at >= "${from}"`, `queued_at < "${to}"`),
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
    routes: await attachRouteUpdates(routes, sessionFilter, signal),
    gateEvents,
    nextCursor: null,
  }
}

export function createCollectionSessionManifest(session: Session): SessionManifest {
  const serverNow = new Date().toISOString()
  const startedAt = session.ephemeral ? new Date(Math.max(Date.parse(session.started_at || session.created), Date.parse(serverNow) - retentionWindowMs(session.retention_minutes))).toISOString() : session.started_at || session.created
  const endedAt = session.active ? null : session.ended_at || session.updated
  const edge = endedAt || serverNow
  return {
    sessionId: session.id,
    name: session.name,
    startedAt,
    endedAt,
    active: session.active,
    ephemeral: session.ephemeral,
    retentionMinutes: session.retention_minutes,
    serverNow,
    watermark: session.updated || edge,
    gateAuditComplete: session.gate_audit_complete,
    gateAuditDrops: session.gate_audit_drops,
    counts: {},
    coverage: { from: startedAt, to: edge },
    transport: 'collections',
  }
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
    const payload = await requestJSON<ListResponse<T>>(`/api/collections/${collection}/records?${params}`, options.signal)
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

/** Compact activity summaries with storage-revision deltas and stable ID pagination. */
export async function readActivityChunkSummaries(sessionId: string, watermark: number, signal: AbortSignal, fromMs = 0): Promise<ActivityChunkSummary[]> {
  const records: ActivityChunkSummary[] = []
  const fields = 'id,session,flow,chunk_start,chunk_ms,wire_bytes_in,wire_bytes_out,capture_complete,dropped_events,updated_at_source,updated'
  let after = ''
  const sessionFilter = `session=${JSON.stringify(sessionId)}`
    + (fromMs ? ` && chunk_start >= ${JSON.stringify(new Date(fromMs - 60_000).toISOString().replace('T', ' '))}` : '')
  // Use storage revision, so a late write of an old capture chunk is still picked up.
  const updatedFilter = watermark ? ` && updated >= ${JSON.stringify(new Date(watermark - 30_000).toISOString().replace('T', ' '))}` : ''
  while (!signal.aborted) {
    const params = new URLSearchParams({ perPage: '500', sort: 'id', fields,
      filter: `${sessionFilter}${updatedFilter}${after ? ` && id > ${JSON.stringify(after)}` : ''}` })
    const payload = await requestJSON<{ items: ActivityChunkSummary[] }>(`/api/collections/flow_activity_chunks/records?${params}`, signal)
    if (!Array.isArray(payload.items)) throw new Error('Missing activity summaries')
    records.push(...payload.items.filter(record => record.session === sessionId && (!fromMs || parseEpoch(record.chunk_start) + record.chunk_ms > fromMs)))
    if (payload.items.length < 500) break
    const next = payload.items[payload.items.length - 1]?.id
    if (!next || next <= after) throw new Error('Activity summary pagination did not advance')
    after = next
  }
  signal.throwIfAborted()
  return records
}
