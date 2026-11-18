import { useEffect, useState } from 'react'
import { getConnectedClients } from '@infrareveal/session-state'
import type { ConnectedClient } from '@infrareveal/session-state'

const POLL_MS = 5_000

export type ConnectedClientsState = { connected: number; clients: ConnectedClient[] }

/** Live Wi-Fi associations for the session the gateway is recording.
 * Returns null for history, simulations, other sessions or an unavailable radio. */
export function useConnectedClients(sessionId: string, enabled: boolean): ConnectedClientsState | null {
  const [state, setState] = useState<(ConnectedClientsState & { sessionId: string }) | null>(null)
  useEffect(() => {
    if (!enabled || !sessionId) return
    let stopped = false
    let timer = 0
    const controller = new AbortController()
    async function poll() {
      try {
        const next = await getConnectedClients(controller.signal)
        if (!stopped) setState(next.available && next.sessionId === sessionId ? { sessionId, connected: next.connected, clients: next.clients ?? [] } : null)
      } catch {
        if (!stopped) setState(null)
      } finally {
        if (!stopped) timer = window.setTimeout(poll, POLL_MS)
      }
    }
    void poll()
    return () => { stopped = true; controller.abort(); window.clearTimeout(timer) }
  }, [sessionId, enabled])
  return enabled && state?.sessionId === sessionId ? state : null
}
