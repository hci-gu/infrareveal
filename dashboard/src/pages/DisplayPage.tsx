import { lazy, Suspense } from 'react'
import { useSessions } from '@infrareveal/session-state'
import { DisplayModeCard } from '../display/DisplayMode'
import { useDisplayMode } from '../display/useDisplayMode'

const MapPage = lazy(() => import('./MapPage').then(module => ({ default: module.MapPage })))

export function DisplayPage() {
  const { state } = useDisplayMode()
  if (state.phase !== 'active' && state.phase !== 'reconnecting') return <main className="display-mode-wait"><DisplayModeCard /></main>
  return <ActiveDisplay />
}

function ActiveDisplay() {
  const { sessions, status, error } = useSessions()
  const session = sessions.find(item => item.active && !item.simulation_expires_ms) ?? sessions.find(item => !item.simulation_expires_ms)
  if (!session) return <main className="display-mode-wait"><section className="display-mode-card">
    <h1>{status === 'offline' ? 'Reconnecting to the gateway' : 'Waiting for a session'}</h1>
    <p role="status">{error || 'This screen will open the map when a session is available.'}</p>
  </section></main>
  return <Suspense fallback={<main className="display-mode-wait">Loading the display…</main>}><MapPage key={session.id} sessionIdOverride={session.id} /></Suspense>
}
