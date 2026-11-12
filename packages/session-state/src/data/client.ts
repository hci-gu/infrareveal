import { seriesKey } from './traffic'
import { baseUrl, requestJSON, requestSignal } from './pocketbaseHttp'
import type { TrafficChunk, Sample, BlockPage, DemoStatus, DiagnosticKind, DiagnosticPage, MapWindow, Session, SessionManifest, SimulationStatus } from './types'
export { baseUrl }
const sessionPath = (id: string) => `/api/infrareveal/sessions/${encodeURIComponent(id)}`
export const getSessions = (signal?: AbortSignal) => requestJSON<{ items: Session[] }>('/api/infrareveal/sessions', signal).then(value => value.items)
export const getSessionManifest = (id: string, signal?: AbortSignal) => requestJSON<SessionManifest>(`${sessionPath(id)}/manifest`, signal)
export const getDemoStatus = (signal?: AbortSignal) => requestJSON<DemoStatus>('/api/infrareveal/demo', signal)
export const getSimulationStatus = (signal?: AbortSignal) => requestJSON<SimulationStatus>('/api/infrareveal/simulation', signal)
export async function startSimulation(): Promise<SimulationStatus> {
  const response = await fetch(`${baseUrl}/api/infrareveal/simulation`, { method: 'POST', signal: requestSignal() })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || 'Could not start demo')
  return response.json()
}
export async function stopSimulation(session: string) {
  const response = await fetch(`${baseUrl}/api/infrareveal/simulation?${new URLSearchParams({ session_id: session })}`, { method: 'DELETE', signal: requestSignal() })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || 'Could not stop demo')
}
export function getBlocks(id: string, from: number, to: number, cursor = '', signal?: AbortSignal, order: 'oldest' | 'latest' = 'oldest') {
  return requestJSON<BlockPage>(`${sessionPath(id)}/blocks?${new URLSearchParams({ from: String(from), to: String(to), cursor, order })}`, signal)
}
export function getDiagnostics(id: string, kind: DiagnosticKind, from: number, to: number, token: string, signal?: AbortSignal) {
  return fetch(`${baseUrl}${sessionPath(id)}/diagnostics/${kind}?${new URLSearchParams({ from: String(from), to: String(to) })}`, { headers: { Authorization: token }, signal: requestSignal(signal) }).then(async response => {
    if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || `Diagnostics unavailable (${response.status})`)
    return response.json() as Promise<DiagnosticPage>
  })
}
/** Assemble bounded pages without quadratic array copies. A partial snapshot is
 * never published, including when capture changes during pagination. */
export async function getMapWindow(id: string, from: number, to: number, resolution = 50, signal?: AbortSignal, block = '', compact = false): Promise<MapWindow> {
  for (let attempt = 0; ; attempt++) {
    let result: MapWindow | undefined
    const seen = new Set<string>(), groups = new Map<string, TrafficChunk>()
    const coverage = new Map<string, MapWindow['coverage'][number]>()
    const blocks = new Map<string, MapWindow['blocks'][number]>()
    const routes = new Map<string, MapWindow['routes'][number]>()
    const destinations = new Map<string, MapWindow['destinations'][number]>()
    let cursor = ''
    try {
      do {
        const params = new URLSearchParams({ from: String(from), to: String(to), resolution: String(resolution), cursor })
        if (block) params.set('block', block)
        if (compact) { params.set('compact', 'true'); params.set('limit', '1000') }
        const page = await requestJSON<MapWindow>(`${sessionPath(id)}/map?${params}`, signal)
        if (result && page.revision !== result.revision) throw new Error('Session changed during window pagination')
        if (!result) result = { ...page, series: [] }
        for (const chunk of page.series) {
          if (!compact) { result.series.push(chunk); continue }
          const key = JSON.stringify([seriesKey(chunk), chunk.bucket_ms, chunk.evidence])
          const previous = groups.get(key)
          if (!previous) { groups.set(key, chunk); result.series.push(chunk) }
          else {
            for (const sample of chunk.samples) previous.samples.push([sample[0] + chunk.start_ms - previous.start_ms, ...sample.slice(1)] as Sample)
            previous.chunk_ms = Math.max(previous.chunk_ms, chunk.start_ms + chunk.chunk_ms - previous.start_ms)
            previous.sealed &&= chunk.sealed
          }
        }
        for (const item of page.coverage) coverage.set(item.id, item)
        for (const item of page.blocks) blocks.set(item.id, item)
        for (const item of page.routes) routes.set(item.id, item)
        for (const item of page.destinations) destinations.set(item.id, item)
        cursor = page.next_cursor || ''
        if ((!page.complete && !cursor) || (cursor && seen.has(cursor))) throw new Error('Invalid map pagination cursor')
        seen.add(cursor)
      } while (cursor)
      return { ...result!, complete: true, next_cursor: undefined, coverage: [...coverage.values()], blocks: [...blocks.values()], routes: [...routes.values()], destinations: [...destinations.values()] }
    } catch (error) {
      if (attempt < 2 && !signal?.aborted && (error instanceof Error && ('status' in error && error.status === 409 || error.message === 'Session changed during window pagination'))) continue
      throw error
    }
  }
}
export async function updateSession(id: string, method: 'POST' | 'PATCH' | 'DELETE', value?: Record<string, unknown>, action = '') {
  const path = id ? `${sessionPath(id)}${action ? `/${action}` : ''}` : '/api/infrareveal/sessions'
  // Removing a large recording can take longer on the Pi's SD card.
  const response = await fetch(`${baseUrl}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: value ? JSON.stringify(value) : undefined, signal: method === 'DELETE' ? AbortSignal.timeout(120_000) : requestSignal() })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || 'Session operation failed')
  return response.status === 204 ? null : response.json()
}
