import { useEffect, useState } from 'react'
import { getDemoStatus } from '@infrareveal/session-state'
import type { DemoStatus } from '@infrareveal/session-state'
import { MapPage } from './MapPage'

/** A stable entry point; a failed first request and a replaced session both recover. */
export function DemoPage() {
  const [status, setStatus] = useState<DemoStatus | null>(null)
  const [error, setError] = useState('')
  useEffect(() => {
    let stopped = false
    let timer = 0
    const controller = new AbortController()
    async function poll() {
      try {
        const next = await getDemoStatus(controller.signal)
        if (!stopped) { setStatus(next); setError('') }
      } catch {
        if (!stopped) setError('Gateway unavailable. Reconnecting automatically…')
      } finally {
        if (!stopped) timer = window.setTimeout(poll, 5_000)
      }
    }
    void poll()
    return () => { stopped = true; controller.abort(); window.clearTimeout(timer) }
  }, [])

  if (status?.enabled && status.sessionId) {
    return <MapPage key={status.sessionId} demo={{ status, error }} sessionIdOverride={status.sessionId} />
  }
  return <main className="min-h-screen bg-slate-950 px-8 text-slate-100 flex flex-col items-center justify-center text-center">
    <p className="text-4xl font-bold">InfraReveal</p>
    <h1 className="mt-8 text-2xl">{status && !status.enabled ? 'Lab demo is not enabled' : 'Waiting for the lab gateway'}</h1>
    <p className="mt-4 text-slate-300" role="status">{error || (status && !status.enabled ? 'Enable lab demo mode on the gateway to start this display.' : 'This screen will connect automatically when the demo is ready.')}</p>
  </main>
}
