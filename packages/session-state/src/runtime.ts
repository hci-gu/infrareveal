import { useCallback, useEffect, useRef, useState } from 'react'
import { useStore } from 'zustand'
import { createStore } from 'zustand/vanilla'
import { baseUrl, getBlocks, getMapWindow, getSessionManifest } from './data/client'
import type { ActivityBlock, ConnectionState, MapWindow, SessionManifest } from './data/types'

export type PlaybackState = 'following' | 'playing' | 'paused'
export type SessionTimelineState = {
  selectedSessionId: string | null; manifest: SessionManifest | null; connectionState: ConnectionState; error: string
  clock: { serverMs: number; receivedMs: number }; epochMs: number; liveEdgeMs: number; cursorMs: number; mode: 'live' | 'recorded'; playback: PlaybackState; rate: number
}
const initial: SessionTimelineState = { selectedSessionId: null, manifest: null, connectionState: 'loading', error: '', clock: { serverMs: 0, receivedMs: 0 }, epochMs: 0, liveEdgeMs: 0, cursorMs: 0, mode: 'recorded', playback: 'paused', rate: 1 }
export const sessionTimelineStore = createStore<SessionTimelineState>(() => initial)
export function setTimelinePlayback(value: Partial<Pick<SessionTimelineState, 'cursorMs' | 'playback' | 'rate'>>) { sessionTimelineStore.setState(value) }

/** Replace facts at a revision boundary; retention never rebases the playback clock. */
export function acceptManifest(manifest: SessionManifest) {
  const previous = sessionTimelineStore.getState()
  if (previous.selectedSessionId !== manifest.id) return
  const first = !previous.manifest
  const edge = manifest.active ? manifest.server_ms : manifest.ended_ms || manifest.capture.confirmed_ms || manifest.started_ms
  sessionTimelineStore.setState({ manifest, clock: { serverMs: manifest.server_ms, receivedMs: performance.now() }, epochMs: manifest.started_ms, liveEdgeMs: edge, mode: manifest.active ? 'live' : 'recorded', error: '',
    cursorMs: first ? manifest.active ? Math.max(manifest.retained_from_ms, edge - 500) : manifest.retained_from_ms : Math.max(manifest.retained_from_ms, Math.min(edge, previous.cursorMs)),
    playback: first ? manifest.active ? 'following' : 'paused' : previous.playback })
  for (const [key, value] of windowCache) if (value.window.session_id === manifest.id && value.window.to_ms <= manifest.retained_from_ms) windowCache.delete(key)
}
let owner: { id: string; users: number; stop: () => void; refresh: () => Promise<void> } | undefined
function watchSession(id: string) {
  if (owner?.id === id) { owner.users++; return release }
  owner?.stop()
  sessionTimelineStore.setState({ ...initial, selectedSessionId: id })
  const controller = new AbortController()
  let timer: ReturnType<typeof setTimeout> | undefined
  let busy = false, dirty = false
  const refresh = async () => {
    if (controller.signal.aborted) return
    if (busy) { dirty = true; return }
    busy = true
    try { acceptManifest(await getSessionManifest(id, controller.signal)) }
    catch (error) { if (!controller.signal.aborted) sessionTimelineStore.setState({ connectionState: 'error', error: error instanceof Error ? error.message : 'Unable to load session' }) }
    finally { busy = false; if (dirty) { dirty = false; schedule() } }
  }
  const schedule = () => { if (!timer) timer = setTimeout(() => { timer = undefined; void refresh() }, 400) }
  const stream = new EventSource(`${baseUrl}/api/infrareveal/sessions/${encodeURIComponent(id)}/revisions`)
  stream.addEventListener('open', () => { if (!controller.signal.aborted) { sessionTimelineStore.setState({ connectionState: 'live' }); schedule() } })
  stream.addEventListener('revision', event => {
    if (controller.signal.aborted) return
    try {
      const next = JSON.parse((event as MessageEvent<string>).data) as { revision: number; retained_from_ms: number; server_ms: number }
      const state = sessionTimelineStore.getState()
      if (!state.manifest || next.revision !== state.manifest.revision || next.retained_from_ms !== state.manifest.retained_from_ms) schedule()
      else if (state.manifest.active) sessionTimelineStore.setState({ liveEdgeMs: next.server_ms, clock: { serverMs: next.server_ms, receivedMs: performance.now() } })
      sessionTimelineStore.setState({ connectionState: 'live', error: '' })
    } catch { schedule() }
  })
  stream.addEventListener('error', () => { if (!controller.signal.aborted) sessionTimelineStore.setState({ connectionState: 'offline', error: 'Gateway disconnected. Loaded history remains available.' }) })
  owner = { id, users: 1, refresh, stop: () => { controller.abort(); stream.close(); clearTimeout(timer) } }
  void refresh()
  return release
  function release() { if (owner?.id === id && --owner.users === 0) { owner.stop(); owner = undefined } }
}
export function useSession(id: string, enabled = true) {
  useEffect(() => enabled && id ? watchSession(id) : undefined, [id, enabled])
  const timeline = useStore(sessionTimelineStore)
  const refresh = useCallback(async () => { await owner?.refresh() }, [])
  return { timeline: timeline.selectedSessionId === id ? timeline : { ...initial, selectedSessionId: id }, refresh }
}

const windowCache = new Map<string, { window: MapWindow; bytes: number }>()
const CACHE_BYTES = 12 * 1024 * 1024
function cacheWindow(key: string, window: MapWindow) {
  windowCache.delete(key)
  windowCache.set(key, { window, bytes: JSON.stringify(window).length * 2 })
  let total = [...windowCache.values()].reduce((sum, entry) => sum + entry.bytes, 0)
  for (const [id, entry] of windowCache) {
    if (total <= CACHE_BYTES && windowCache.size <= 12) break
    total -= entry.bytes; windowCache.delete(id)
  }
}
export const emptyMapWindow = (id = '', from = 0, to = 0, resolution = 50): MapWindow => ({ session_id: id, revision: 0, from_ms: from, to_ms: to, resolution_ms: resolution, complete: false, series: [], coverage: [], blocks: [], destinations: [], routes: [] })
export function useMapWindow(id: string, from: number, to: number, resolution = 50, block = '', enabled = true) {
  const revision = useStore(sessionTimelineStore, state => state.selectedSessionId === id ? state.manifest?.revision ?? 0 : 0)
  const key = JSON.stringify([id, from, to, resolution, block])
  const [state, setState] = useState<{ key: string; window: MapWindow; loading: boolean; error: string }>({ key: '', window: emptyMapWindow(), loading: false, error: '' })
  const [retry, setRetry] = useState(0)
  const pending = useRef<{ key: string; controller: AbortController } | null>(null)
  useEffect(() => () => { pending.current?.controller.abort(); pending.current = null }, [key])
  useEffect(() => {
    if (!id || !enabled || !revision || to <= from) return
    const cached = windowCache.get(key)
    if (cached && cached.window.revision >= revision || pending.current?.key === key) return
    pending.current?.controller.abort()
    const controller = new AbortController()
    pending.current = { key, controller }
    void getMapWindow(id, from, to, resolution, controller.signal, block).then(window => {
      if (controller.signal.aborted) return
      cacheWindow(key, window); setState({ key, window, loading: false, error: '' })
      if ((sessionTimelineStore.getState().manifest?.revision ?? 0) > window.revision) setRetry(value => value + 1)
    }).catch(error => { if (!controller.signal.aborted) setState({ key, window: emptyMapWindow(id, from, to, resolution), loading: false, error: error instanceof Error ? error.message : 'Unable to load map window' }) })
      .finally(() => { if (pending.current?.controller === controller) pending.current = null })
  }, [id, from, to, resolution, block, enabled, revision, key, retry])
  const cached = windowCache.get(key)?.window
  const active = state.key === key ? state : null
  const refresh = useCallback(() => { windowCache.delete(key); setRetry(value => value + 1) }, [key])
  return { window: cached ?? active?.window ?? emptyMapWindow(id, from, to, resolution), loading: enabled && Boolean(id && revision && to > from) && !cached && !active, error: active?.error || '', refresh }
}

/** Reload the loaded page span atomically when a revision invalidates its cursor. */
export function useActivityBlocks(id: string, from: number, to: number) {
  const revision = useStore(sessionTimelineStore, state => state.selectedSessionId === id ? state.manifest?.revision ?? 0 : 0)
  const key = JSON.stringify([id, from, to])
  const [state, setState] = useState<{ key: string; items: ActivityBlock[]; next: string; loading: boolean; error: string }>({ key: '', items: [], next: '', loading: false, error: '' })
  const [pages, setPages] = useState({ key: '', count: 1 }), [retry, setRetry] = useState(0)
  const count = pages.key === key ? pages.count : 1
  const pending = useRef<AbortController | null>(null)
  useEffect(() => () => { pending.current?.abort(); pending.current = null }, [key, count])
  useEffect(() => {
    if (!id || !revision || to <= from || pending.current) return
    const controller = new AbortController()
    pending.current = controller
    const load = async () => {
      for (let attempt = 0; attempt < 3; attempt++) {
        try {
          const items: ActivityBlock[] = []
          let cursor = '', pageRevision = 0
          for (let pageNumber = 0; pageNumber < count; pageNumber++) {
            const page = await getBlocks(id, from, to, cursor, controller.signal)
            if (pageRevision && pageRevision !== page.revision) throw new Error('Session changed during block pagination')
            pageRevision = page.revision; items.push(...page.items); cursor = page.next_cursor || ''
            if (!cursor) break
          }
          if (!controller.signal.aborted) {
            setState({ key, items, next: cursor, loading: false, error: '' })
            if ((sessionTimelineStore.getState().manifest?.revision ?? 0) > pageRevision) setRetry(value => value + 1)
          }
          return
        } catch (error) {
          if (controller.signal.aborted) return
          if (attempt < 2 && error instanceof Error && (('status' in error && error.status === 409) || error.message === 'Session changed during block pagination')) continue
          setState(value => ({ key, items: value.key === key ? value.items : [], next: '', loading: false, error: error instanceof Error ? error.message : 'Unable to load activity blocks' }))
        }
      }
    }
    void load().finally(() => { if (pending.current === controller) pending.current = null })
  }, [id, from, to, revision, key, count, retry])
  const current = state.key === key ? state : { key, items: [], next: '', loading: Boolean(id), error: '' }
  return { ...current, more: () => setPages({ key, count: count + 1 }), refresh: () => setRetry(value => value + 1) }
}
