import { requestJSON } from './pocketbaseHttp'
import { emptySessionWindow, mergeSessionWindows } from './sessionData'
import { normalizeRouteRecord } from './routeRecords'
import type { SessionManifest, SessionWindow, SessionWindowRequest } from './types'

export async function getTimelineSessionManifest(sessionId: string, signal?: AbortSignal): Promise<SessionManifest> {
  const manifest = await requestJSON<SessionManifest>(`/api/infrareveal/sessions/${encodeURIComponent(sessionId)}/manifest`, signal)
  return { ...manifest, transport: 'timeline' }
}

export async function getTimelineSessionWindow({
  sessionId,
  fromMs,
  toMs,
  lod,
  flowIds = [],
  signal,
}: SessionWindowRequest): Promise<SessionWindow> {
  let merged = emptySessionWindow(fromMs, toMs, lod)
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
    page.routes = (page.routes ?? []).map(route => normalizeRouteRecord(route))
    merged = mergeSessionWindows(merged, page)
    cursor = page.nextCursor
  } while (cursor)
  merged.nextCursor = null
  return merged
}
