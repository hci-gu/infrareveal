import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { getSimulationStatus, stopSimulation } from '@infrareveal/session-state'

export function SimulationBanner({ session, expiresMS, serverMS }: { session: string; expiresMS: number; serverMS: number }) {
  const navigate = useNavigate()
  const [clock] = useState(() => ({ serverMS, receivedAt: performance.now() }))
  const [remaining, setRemaining] = useState(() => Math.max(0, Math.ceil((expiresMS - serverMS) / 1000)))
  const [stopping, setStopping] = useState(false)
  const [error, setError] = useState('')

  useEffect(() => {
    const controller = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const check = async () => {
      setRemaining(Math.max(0, Math.ceil((expiresMS - clock.serverMS - (performance.now() - clock.receivedAt)) / 1000)))
      try {
        const status = await getSimulationStatus(controller.signal)
        if (!controller.signal.aborted && (!status.active || status.session_id !== session)) {
          navigate('/', { replace: true, state: { simulationFinished: true } })
          return
        }
      } catch { /* Keep the map and retry until cleanup is confirmed. */ }
      if (!controller.signal.aborted) timer = setTimeout(() => void check(), 1000)
    }
    timer = setTimeout(() => void check(), 1000)
    return () => { controller.abort(); clearTimeout(timer) }
  }, [session, expiresMS, clock, navigate])

  const stop = async () => {
    setStopping(true)
    setError('')
    try {
      await stopSimulation(session)
      navigate('/', { replace: true, state: { simulationFinished: true } })
    } catch (error) {
      setError(error instanceof Error ? error.message : 'Could not stop demo')
      setStopping(false)
    }
  }

  return <div className="atlas-connection-notice">
    <span>Simulated traffic · {remaining ? `auto-deletes in ${Math.floor(remaining / 60)}:${String(remaining % 60).padStart(2, '0')}` : 'cleaning up…'}{error && <span role="alert"> · {error}</span>}</span>
    <button type="button" disabled={stopping} onClick={() => void stop()}>{stopping ? 'Cleaning up…' : 'Stop and clean up'}</button>
  </div>
}
