import type { GatewayData, SessionWindow, TimelineLOD } from './types'

type SessionRecords = Omit<SessionWindow, 'range' | 'lod' | 'watermark' | 'nextCursor'>

function emptySessionRecords(): SessionRecords {
  return {
    flows: [], dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [],
    flowActivityChunks: [], flowActivityWindows: [], flowActivityStatuses: [],
    destinations: [], routes: [], gateEvents: [],
  }
}

export function emptyGatewayData(): GatewayData {
  return { sessions: [], selectedSession: null, ...emptySessionRecords() }
}

export function emptySessionWindow(fromMs: number, toMs: number, lod: TimelineLOD): SessionWindow {
  return {
    range: { from: new Date(fromMs).toISOString(), to: new Date(toMs).toISOString() },
    lod, watermark: '', nextCursor: null, ...emptySessionRecords(),
  }
}

/** Used for both timeline cursors and separately requested flow batches. Every
 * collection, including gate events, follows the same identity merge rule. */
export function mergeSessionWindows(current: SessionWindow, incoming: SessionWindow): SessionWindow {
  return {
    ...incoming,
    watermark: incoming.watermark || current.watermark,
    flows: mergeById(current.flows, incoming.flows),
    dnsQueries: mergeById(current.dnsQueries, incoming.dnsQueries),
    attributions: mergeById(current.attributions, incoming.attributions),
    activityEpisodes: mergeById(current.activityEpisodes, incoming.activityEpisodes),
    flowAssociations: mergeById(current.flowAssociations, incoming.flowAssociations),
    flowActivityChunks: mergeById(current.flowActivityChunks, incoming.flowActivityChunks),
    flowActivityWindows: mergeById(current.flowActivityWindows, incoming.flowActivityWindows),
    flowActivityStatuses: mergeById(current.flowActivityStatuses, incoming.flowActivityStatuses),
    destinations: mergeById(current.destinations, incoming.destinations),
    routes: mergeById(current.routes, incoming.routes),
    gateEvents: mergeById(current.gateEvents, incoming.gateEvents),
  }
}

export function mergeById<T extends { id: string }>(current: T[], incoming: T[] = []) {
  const records = new Map(current.map(record => [record.id, record]))
  for (const record of incoming) records.set(record.id, record)
  return [...records.values()]
}
