import { useEffect, useState } from 'react'
import { BrowserRouter, Navigate, Route, Routes, useLocation, useNavigate } from 'react-router-dom'
import { getSessions } from '@infrareveal/session-state'
import { ProxyLabPage } from './experiments/proxy-lab/ProxyLabPage'
import { SessionPlaybackPage } from './experiments/session-playback/SessionPlaybackPage'
import { ExperimentsPage } from './pages/ExperimentsPage'
import { ControlledClientPage } from './pages/ControlledClientPage'

function ActiveSessionRedirect({ experiment }: { experiment: 'timeline' | 'proxy-lab' }) {
  const navigate = useNavigate()
  const location = useLocation()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const controller = new AbortController()
    getSessions(controller.signal)
      .then((sessions) => {
        const search = new URLSearchParams(location.search)
        const legacySession = search.get('session')
        search.delete('session')
        const selected = sessions.find((session) => session.id === legacySession)
          ?? sessions.find((session) => session.active)
          ?? sessions[0]
        if (!selected) {
          setError('No gateway session is available yet.')
          return
        }
        const query = search.toString()
        navigate(`/${experiment}/${selected.id}${query ? `?${query}` : ''}`, { replace: true })
      })
      .catch((loadError: unknown) => {
        if (!controller.signal.aborted) {
          setError(loadError instanceof Error ? loadError.message : 'Unable to load gateway sessions.')
        }
      })
    return () => controller.abort()
  }, [experiment, location.search, navigate])

  return (
    <main className="grid min-h-screen place-items-center bg-slate-950 px-6 text-slate-100">
      <div className="max-w-lg border border-slate-800 bg-slate-900 p-8 text-center">
        <p className="text-xs font-semibold uppercase tracking-[0.18em] text-cyan-400">InfraReveal debug lab</p>
        <h1 className="mt-3 text-2xl font-semibold">{error ?? 'Opening the active session…'}</h1>
        {error ? <a className="mt-5 inline-block text-sm font-semibold text-cyan-300 underline" href="/">Back to experiments</a> : null}
      </div>
    </main>
  )
}

export default function App() {
  return (
    <BrowserRouter>
      <Routes>
        <Route element={<ExperimentsPage />} path="/" />
        <Route element={<ControlledClientPage />} path="/controlled-client" />
        <Route element={<ActiveSessionRedirect experiment="timeline" />} path="/timeline" />
        <Route element={<SessionPlaybackPage />} path="/timeline/:sessionID" />
        <Route element={<ActiveSessionRedirect experiment="proxy-lab" />} path="/proxy-lab" />
        <Route element={<ProxyLabPage />} path="/proxy-lab/:sessionID" />
        <Route element={<Navigate replace to="/" />} path="*" />
      </Routes>
    </BrowserRouter>
  )
}
