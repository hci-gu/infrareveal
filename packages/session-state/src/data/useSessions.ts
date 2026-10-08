import { useCallback, useEffect, useRef, useState } from 'react'
import { getSessions } from './collectionTransport'
import type { Session } from './types'

type SessionList = { sessions: Session[]; status: 'loading' | 'ready' | 'offline'; error: string; revision: number }
const initial: SessionList = { sessions: [], status: 'loading', error: '', revision: 0 }

/** Each mounted library owns its requests; polling keeps the last successful list. */
export function useSessions(pollMs = 0, requestKey = '') {
  const [state, setState] = useState({ ...initial, requestKey })
  const request = useRef(() => {})
  useEffect(() => {
    const controller = new AbortController()
    let busy = false
    const load = async (refresh = false) => {
      if (controller.signal.aborted || busy) return
      busy = true
      if (refresh && !pollMs) setState(current => ({ ...current, status: 'loading', error: '' }))
      try {
        const sessions = await getSessions(controller.signal)
        if (!controller.signal.aborted) setState(current => ({ sessions, status: 'ready', error: '', revision: current.revision + 1, requestKey }))
      } catch (error) {
        if (!controller.signal.aborted) setState(current => ({ ...current, status: 'offline', error: error instanceof Error ? error.message : 'Unable to load sessions', requestKey }))
      } finally { busy = false }
    }
    request.current = () => void load(true)
    const first = setTimeout(() => void load(), 0)
    const poll = pollMs ? setInterval(() => void load(), pollMs) : undefined
    return () => { controller.abort(); clearTimeout(first); clearInterval(poll) }
  }, [pollMs, requestKey])
  const refresh = useCallback(() => request.current(), [])
  return { ...(state.requestKey === requestKey ? state : initial), refresh }
}
