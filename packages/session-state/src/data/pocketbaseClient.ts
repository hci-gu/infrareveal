import { baseUrl, isNotFound, requestJSON } from './pocketbaseHttp'
import { createCollectionSessionManifest, getCollectionSessionWindow, getSessions } from './collectionTransport'
import { getTimelineSessionManifest, getTimelineSessionWindow } from './timelineTransport'
import type { SessionWindowRequest } from './types'

export { createCollectionSessionManifest, getCollectionSessionWindow, getSessions, readActivityChunkSummaries } from './collectionTransport'
export { emptyGatewayData } from './sessionData'
export { pb } from './realtime'
export type { RealtimeEvent } from './realtime'

/** Prefer timeline routes; only a missing endpoint selects older-gateway compatibility. */
export async function getSessionManifest(sessionId: string, signal?: AbortSignal) {
  try {
    return await getTimelineSessionManifest(sessionId, signal)
  } catch (error) {
    if (!isNotFound(error)) throw error
    const session = (await getSessions(signal)).find(candidate => candidate.id === sessionId)
    if (!session) throw error
    return createCollectionSessionManifest(session)
  }
}

export async function getSessionWindow(options: SessionWindowRequest) {
  try {
    return await getTimelineSessionWindow(options)
  } catch (error) {
    if (!isNotFound(error)) throw error
    return getCollectionSessionWindow(options)
  }
}

export type ClearGatewayDataResult = {
  deleted: Record<string, number>
  skipped: string[]
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

export type RouteDiscoveryStatus = {
  session?: string
  engine?: string
  pending: number
  running: number
  starts: number
  cache_hits: number
  failures: number
  deferred: number
  oldest_wait_ms: number
  last_error: string
  measured_byte_coverage: number
  recent_bytes: number
  useful_paths?: number
  unique_useful_bindings?: number
  no_gain_attempts?: number
  suppressed_attempts?: number
  duplicate_publications_avoided?: number
  evidence_bytes_written?: number
  budget_remaining?: number
  manual_remaining?: number
  coverage_running?: number
  reached_byte_coverage?: number
  located_byte_coverage?: number
  hop_coverage?: number
  targets?: Array<{ destination_ip: string; destination_port: number; protocol: string; state: string }>
  access_context?: Array<{
    prefix: Array<{ ttl: number; addresses: string[] }>
    witnesses: Array<{ ip: string; attempt: string; at: string }>
  }>
}

export function getRouteDiscoveryStatus(signal?: AbortSignal) {
  return requestJSON<RouteDiscoveryStatus>('/api/infrareveal/routes/status', signal)
}

export async function measureRoute(flowId: string) {
  const response = await fetch(`${baseUrl}/api/infrareveal/routes/measure`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ flow_id: flowId }),
  })
  if (!response.ok) throw new Error((await response.json()).message || 'Unable to request measurement')
}

export async function extendRouteBudget() {
  const response = await fetch(`${baseUrl}/api/infrareveal/routes/extend-budget`, { method: 'POST' })
  if (!response.ok) throw new Error('Unable to extend route budget')
}

export type DemoStatus = {
  serverNow: string
  enabled: boolean
  sessionId?: string
  ssid: string
  retentionMinutes?: number
  observing?: boolean
  catalogueEnabled: boolean
  maintenance: { lastSuccess: string; lastError: string }
  capture?: { running: boolean; reportedAt: string; lastError: string }
}

export function getDemoStatus(signal?: AbortSignal) {
  return requestJSON<DemoStatus>('/api/infrareveal/demo', signal)
}
