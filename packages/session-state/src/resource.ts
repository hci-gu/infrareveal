import { useCallback, useEffect, useRef, useState } from 'react'

type WindowRequest = { key: string; scope: string; from: number; to: number }
export type Snapshot<T> = WindowRequest & { data: T }

/** Only overlapping, forward live windows can borrow the previous snapshot. */
function continuesWindow(previous: WindowRequest, next: WindowRequest) {
  return previous.scope === next.scope && next.from >= previous.from && next.from < previous.to
    && next.to >= previous.to
}

/** Keep successful facts separate from request status. Revisions coalesce while a request is running. */
export function useRevisionResource<T extends { revision: number }>(request: WindowRequest, revision: number, enabled: boolean, keepPrevious: boolean,
  fetcher: (signal: AbortSignal) => Promise<T>, cached?: Snapshot<T>, onLoad?: (snapshot: Snapshot<T>) => void) {
  const { key, scope, from, to } = request
  const [state, setState] = useState<{ snapshot?: Snapshot<T>; key: string; pending: boolean; error: string }>({ key: '', pending: false, error: '' })
  const [retry, setRetry] = useState(0)
  const pending = useRef<AbortController | null>(null)
  const timer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined)
  const waiting = useRef(false)
  const latestRevision = useRef(revision)
  const successfulRevision = useRef(0)
  useEffect(() => {
    successfulRevision.current = 0
    waiting.current = false
    return () => { pending.current?.abort(); pending.current = null; clearTimeout(timer.current) }
  }, [key, enabled])
  useEffect(() => {
    latestRevision.current = revision
    if (!enabled || !revision || pending.current || waiting.current || Math.max(cached?.data.revision ?? 0, successfulRevision.current) >= revision) return
    const controller = new AbortController()
    pending.current = controller
    clearTimeout(timer.current)
    setState(value => ({ ...value, key, pending: true, error: '' }))
    void fetcher(controller.signal).then(data => {
      if (controller.signal.aborted) return
      successfulRevision.current = data.revision
      const snapshot = { key, scope, from, to, data }
      onLoad?.(snapshot)
      if (data.revision < latestRevision.current) {
        waiting.current = true
        timer.current = setTimeout(() => { waiting.current = false; setRetry(value => value + 1) }, 250)
      }
      setState({ snapshot, key, pending: false, error: '' })
    }).catch(error => {
      if (controller.signal.aborted) return
      waiting.current = true
      setState(value => ({ ...value, key, pending: false, error: error instanceof Error ? error.message : 'Unable to load session data' }))
      timer.current = setTimeout(() => { waiting.current = false; setRetry(value => value + 1) }, 2000)
    }).finally(() => { if (pending.current === controller) pending.current = null })
  }, [key, scope, from, to, revision, enabled, fetcher, cached, onLoad, retry])
  // A cache hit is also the last successful snapshot for the next live range.
  if (cached && cached !== state.snapshot) setState(value => ({ ...value, snapshot: cached }))
  const candidate = cached ?? state.snapshot
  const snapshot = enabled && candidate && (candidate.key === key || (candidate.scope === scope && candidate.from === from && candidate.to === to) || (keepPrevious && continuesWindow(candidate, request))) ? candidate : undefined
  const error = state.key === key ? state.error : ''
  const refreshing = Boolean(snapshot && (snapshot.key !== key || snapshot.data.revision < revision || (state.key === key && state.pending)))
  const refresh = useCallback(() => { successfulRevision.current = 0; waiting.current = false; clearTimeout(timer.current); setRetry(value => value + 1) }, [])
  return { snapshot, hasData: Boolean(snapshot), loading: enabled && !snapshot && !error, refreshing, error, refresh }
}
