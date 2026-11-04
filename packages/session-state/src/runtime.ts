import { useCallback, useEffect, useMemo, useState } from 'react'
import { useRevisionResource } from './resource'
import type { Snapshot } from './resource'
import { useStore } from 'zustand'
import { createStore } from 'zustand/vanilla'
import { baseUrl, getBlocks, getMapWindow, getSessionManifest } from './data/client'
import type { BlockPage, ConnectionState, MapWindow, SessionManifest } from './data/types'

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
  for (const [key, value] of windowCache) if (value.snapshot.data.session_id === manifest.id && value.snapshot.data.to_ms <= manifest.retained_from_ms) windowCache.delete(key)
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
  const onRevision = (event: Event) => {
    if (controller.signal.aborted) return
    try {
      const next = JSON.parse((event as MessageEvent<string>).data) as { revision: number; retained_from_ms: number; server_ms: number }
      const state = sessionTimelineStore.getState()
      if (!state.manifest || next.revision !== state.manifest.revision || next.retained_from_ms !== state.manifest.retained_from_ms) schedule()
      else if (state.manifest.active) sessionTimelineStore.setState({ liveEdgeMs: next.server_ms, clock: { serverMs: next.server_ms, receivedMs: performance.now() } })
      sessionTimelineStore.setState({ connectionState: 'live', error: '' })
    } catch { schedule() }
  }
  stream.addEventListener('revision', onRevision)
  stream.addEventListener('heartbeat', onRevision)
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

const windowCache = new Map<string, { snapshot: Snapshot<MapWindow>; bytes: number }>()
const CACHE_BYTES = 12 * 1024 * 1024
function cacheWindow(snapshot: Snapshot<MapWindow>) {
  windowCache.delete(snapshot.key)
  windowCache.set(snapshot.key, { snapshot, bytes: JSON.stringify(snapshot.data).length * 2 })
  let total = [...windowCache.values()].reduce((sum, entry) => sum + entry.bytes, 0)
  for (const [id, entry] of windowCache) {
    if (total <= CACHE_BYTES && windowCache.size <= 12) break
    total -= entry.bytes; windowCache.delete(id)
  }
}
export const emptyMapWindow = (id = '', from = 0, to = 0, resolution = 50): MapWindow => ({ session_id: id, revision: 0, from_ms: from, to_ms: to, resolution_ms: resolution, complete: false, series: [], coverage: [], blocks: [], destinations: [], routes: [] })

/** Expired samples must not reappear while the replacement window is in flight. */
function retainedWindow(window: MapWindow, floor: number): MapWindow {
  if (floor <= window.from_ms) return window
  return { ...window, from_ms: Math.min(floor, window.to_ms), series: window.series.flatMap(chunk => {
    const samples = chunk.samples.filter(sample => chunk.start_ms + sample[0] >= floor)
    return samples.length ? [{ ...chunk, samples }] : []
  }), coverage: window.coverage.filter(interval => interval.end_ms > floor).map(interval => ({ ...interval, start_ms: Math.max(floor, interval.start_ms) })),
  blocks: window.blocks.filter(block => block.end_ms > floor) }
}

export function useMapWindow(id: string, from: number, to: number, resolution = 50, block = '', enabled = true, continuityScope = '') {
  const manifest = useStore(sessionTimelineStore, state => state.selectedSessionId === id ? state.manifest : null)
  const following = useStore(sessionTimelineStore, state => state.selectedSessionId === id && state.mode === 'live' && state.playback === 'following')
  const scope = JSON.stringify([id, resolution, block, continuityScope, manifest?.capture.epoch])
  const key = JSON.stringify([scope, from, to])
  const fetcher = useCallback((signal: AbortSignal) => getMapWindow(id, from, to, resolution, signal, block), [id, from, to, resolution, block])
  const resource = useRevisionResource({ key, scope, from, to }, manifest?.revision ?? 0, enabled && Boolean(id) && to > from, following,
    fetcher, windowCache.get(key)?.snapshot, cacheWindow)
  const loaded = resource.snapshot?.data
  const floor = manifest?.retained_from_ms ?? from
  const window = useMemo(() => loaded ? retainedWindow(loaded, Math.max(loaded.from_ms, floor)) : emptyMapWindow(id, from, to, resolution), [loaded, floor, id, from, to, resolution])
  const retry = resource.refresh
  const refresh = useCallback(() => { windowCache.delete(key); retry() }, [key, retry])
  return { window, loading: resource.loading, hasData: resource.hasData, refreshing: resource.refreshing, error: resource.error, refresh }
}

/** Reload the loaded page span atomically; live range changes retain visible summaries. */
export function useActivityBlocks(id: string, from: number, to: number, order: 'oldest' | 'latest' = 'oldest') {
  const manifest = useStore(sessionTimelineStore, state => state.selectedSessionId === id ? state.manifest : null)
  const following = useStore(sessionTimelineStore, state => state.selectedSessionId === id && state.mode === 'live' && state.playback === 'following')
  const scope = JSON.stringify([id, order, manifest?.capture.epoch])
  const [pages, setPages] = useState({ scope, count: 1 })
  const count = pages.scope === scope ? pages.count : 1
  const key = JSON.stringify([scope, from, to, count])
  const fetcher = useCallback(async (signal: AbortSignal): Promise<BlockPage> => {
    for (let attempt = 0; ; attempt++) {
      try {
        const items: BlockPage['items'] = []
        let cursor = '', revision = 0
        for (let pageNumber = 0; pageNumber < count; pageNumber++) {
          const page = await getBlocks(id, from, to, cursor, signal, order)
          if (revision && revision !== page.revision) throw new Error('Session changed during block pagination')
          revision = page.revision; items.push(...page.items); cursor = page.next_cursor || ''
          if (!cursor) break
        }
        return { session_id: id, revision, items, next_cursor: cursor }
      } catch (error) {
        if (attempt < 2 && !signal.aborted && error instanceof Error && (('status' in error && error.status === 409) || error.message === 'Session changed during block pagination')) continue
        throw error
      }
    }
  }, [id, from, to, count, order])
  const resource = useRevisionResource({ key, scope, from, to }, manifest?.revision ?? 0, Boolean(id) && to > from, following, fetcher)
  const data = resource.snapshot?.data
  const floor = manifest?.retained_from_ms ?? from
  // A block crossing a new retention floor has old totals; wait for the clipped replacement.
  const items = useMemo(() => data?.items.filter(block => block.start_ms >= floor) ?? [], [data, floor])
  return { items, next: data?.next_cursor ?? '', loading: resource.loading, refreshing: resource.refreshing, error: resource.error,
    hasData: resource.hasData, refresh: resource.refresh, more: () => setPages({ scope, count: count + 1 }) }
}
