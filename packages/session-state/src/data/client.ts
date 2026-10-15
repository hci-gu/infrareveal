import { baseUrl, requestJSON, requestSignal } from './pocketbaseHttp'
import type { ActivityBlock, BlockPage, DemoStatus, DiagnosticKind, DiagnosticPage, MapWindow, Session, SessionManifest } from './types'
export { baseUrl }
const sessionPath = (id: string) => `/api/infrareveal/sessions/${encodeURIComponent(id)}`
export const getSessions = (signal?: AbortSignal) => requestJSON<Session[] | { items: Session[] }>('/api/infrareveal/sessions', signal).then(value => Array.isArray(value) ? value : value.items)
export const getSessionManifest = (id: string, signal?: AbortSignal) => requestJSON<SessionManifest>(`${sessionPath(id)}/manifest`, signal)
export const getDemoStatus = (signal?: AbortSignal) => requestJSON<DemoStatus>('/api/infrareveal/demo', signal)
export const getBlock = (id: string, block: string, signal?: AbortSignal) => requestJSON<ActivityBlock>(`${sessionPath(id)}/blocks/${encodeURIComponent(block)}`, signal)
export function getBlocks(id: string, from: number, to: number, cursor = '', signal?: AbortSignal) {
  return requestJSON<BlockPage>(`${sessionPath(id)}/blocks?${new URLSearchParams({ from: String(from), to: String(to), cursor })}`, signal)
}
export function getDiagnostics(id: string, kind: DiagnosticKind, from: number, to: number, token: string, signal?: AbortSignal) {
  return fetch(`${baseUrl}${sessionPath(id)}/diagnostics/${kind}?${new URLSearchParams({ from: String(from), to: String(to) })}`, { headers: { Authorization: token }, signal: requestSignal(signal) }).then(async response => {
    if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || `Diagnostics unavailable (${response.status})`)
    return response.json() as Promise<DiagnosticPage>
  })
}
export async function measureRoute(chunkID: string) {
  const response = await fetch(`${baseUrl}/api/infrareveal/routes/measure`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ chunk_id: chunkID }), signal: requestSignal() })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || 'Route measurement unavailable')
  return response.json()
}
/** Assemble a revision-consistent window. Never publish an incomplete page set. */
export async function getMapWindow(id: string, from: number, to: number, resolution = 50, signal?: AbortSignal, block = ''): Promise<MapWindow> {
  for (let attempt = 0; ; attempt++) {
    let result: MapWindow | undefined
    const seen = new Set<string>()
    let cursor = ''
    try {
      do {
        const params = new URLSearchParams({ from: String(from), to: String(to), resolution: String(resolution), cursor })
        if (block) params.set('block', block)
        const page = await requestJSON<MapWindow>(`${sessionPath(id)}/map?${params}`, signal)
        if (result && page.revision !== result.revision) throw new Error('Session changed during window pagination')
        result = result ? { ...result, complete: page.complete, next_cursor: page.next_cursor, series: [...result.series, ...page.series], destinations: [...new Map([...result.destinations, ...page.destinations].map(d => [d.id, d])).values()] } : page
        cursor = page.next_cursor || ''
        if ((!page.complete && !cursor) || (cursor && seen.has(cursor))) throw new Error('Invalid map pagination cursor')
        seen.add(cursor)
      } while (cursor)
      return result!
    } catch (error) {
      if (attempt < 2 && !signal?.aborted && (error instanceof Error && ('status' in error && error.status === 409 || error.message === 'Session changed during window pagination'))) continue
      throw error
    }
  }
}
export async function updateSession(id: string, method: 'POST' | 'PATCH' | 'DELETE', value?: Record<string, unknown>, action = '') {
  const path = id ? `${sessionPath(id)}${action ? `/${action}` : ''}` : '/api/infrareveal/sessions'
  const response = await fetch(`${baseUrl}${path}`, { method, headers: { 'Content-Type': 'application/json' }, body: value ? JSON.stringify(value) : undefined, signal: requestSignal() })
  if (!response.ok) throw new Error((await response.json().catch(() => null))?.message || 'Session operation failed')
  return response.status === 204 ? null : response.json()
}
