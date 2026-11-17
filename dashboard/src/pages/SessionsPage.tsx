import { useState } from 'react'
import { Link, useLocation, useNavigate } from 'react-router-dom'
import { startSimulation, useSessions } from '@infrareveal/session-state'
import type { Session } from '@infrareveal/session-state'
import { DeleteSession } from '../maintenance/DeleteSession'
import { DisplayModeCard } from '../display/DisplayMode'
import { MapIcon } from '../map/MapIcon'

const dateFormatter = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function SessionsPage() {
  const { sessions, status, error, refresh: loadSessions } = useSessions()
  const navigate = useNavigate()
  const location = useLocation()
  const [startingDemo, setStartingDemo] = useState(false)
  const [demoError, setDemoError] = useState('')
  const runDemo = async () => {
    setStartingDemo(true)
    setDemoError('')
    try {
      const demo = await startSimulation()
      if (!demo.session_id) throw new Error('Demo did not return a session')
      navigate(`/map/${encodeURIComponent(demo.session_id)}`)
    } catch (error) {
      setDemoError(error instanceof Error ? error.message : 'Could not start demo')
    } finally { setStartingDemo(false) }
  }

  const activeCount = sessions.filter((session) => session.active).length

  return (
    <main className="min-h-dvh bg-paper text-ink">
      <header className="border-b border-rule bg-paper-2">
        <div className="mx-auto flex h-14 max-w-5xl items-center justify-between gap-4 px-4 sm:px-8">
          <span className="flex items-center gap-3">
            <span className="grid size-8 place-items-center rounded-panel border border-rule-2 text-accent" aria-hidden="true"><MapIcon name="globe" size={20} /></span>
            <span className="text-lg font-semibold tracking-tight">infra<span className="font-normal text-accent">reveal</span></span>
          </span>
          <Link to="/storage" className="whitespace-nowrap rounded-card px-2 py-2 text-ui text-muted hover:text-ink focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus">Storage &amp; maintenance</Link>
        </div>
      </header>
      <section className="mx-auto max-w-5xl px-4 py-10 sm:px-8">
        <header className="mb-8 flex flex-col justify-between gap-2 sm:flex-row sm:items-end">
          <div>
            <h1 className="text-2xl font-semibold tracking-tight">Sessions</h1>
            <p className="mt-2 max-w-2xl text-sm text-muted">
              Open a recorded session or follow an active session on the shared timeline map.
            </p>
          </div>
          {status === 'ready' && sessions.length > 0 ? (
            <p className="font-outlier text-ui text-muted tabular-nums">
              {sessions.length} total, <span className="text-down">{activeCount} live</span>
            </p>
          ) : null}
        </header>

        <DisplayModeCard />

        <section className="mb-10 flex flex-wrap items-center justify-between gap-4 border-t border-rule pt-5" aria-label="Traffic simulation">
          <div>
            <h2 className="text-md font-semibold">Try a live traffic demo</h2>
            <p className="mt-1 text-sm text-muted">Eight simulated clients, 144 traffic lanes. Runs for 3 minutes, then deletes its data.</p>
            {location.state?.simulationFinished && <p className="mt-2 text-sm text-success" role="status">Demo finished. Its session and traffic data have been removed.</p>}
            {demoError && <p className="mt-2 text-sm text-error" role="alert">{demoError}</p>}
          </div>
          <button type="button" disabled={startingDemo} onClick={() => void runDemo()} className="h-9 whitespace-nowrap rounded-card border border-field-edge px-4 text-sm font-semibold text-ink hover:border-ink-2 hover:bg-paper-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus active:bg-paper-2 disabled:cursor-not-allowed disabled:text-faint disabled:opacity-60">
            {startingDemo ? 'Starting demo…' : sessions.some(session => session.simulation_expires_ms) ? 'Open running demo' : 'Run 3-minute demo'}
          </button>
        </section>

        {status === 'loading' ? <SessionsLoading /> : null}
        {status === 'offline' ? (
          <div className="border-y border-rule py-8">
            <h2 className="text-lg font-semibold text-error">Could not load sessions</h2>
            <p className="mt-2 text-sm text-muted">{error}</p>
            <button
              type="button"
              onClick={() => void loadSessions()}
              className="mt-5 h-9 rounded-card border border-field-edge px-4 text-sm font-semibold text-ink hover:bg-paper-3 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus active:bg-paper-2"
            >
              Retry
            </button>
          </div>
        ) : null}
        {status === 'ready' && sessions.length === 0 ? (
          <div className="border-y border-dashed border-rule-2 py-12 text-center">
            <h2 className="text-lg font-semibold">No sessions yet</h2>
            <p className="mt-2 text-sm text-muted">
              Sessions will appear here once capture has started.
            </p>
          </div>
        ) : null}
        {status === 'ready' && sessions.length > 0 ? (
          <ul className="border-t border-rule">
            {sessions.map((session) => (
              <li key={session.id} className="border-b border-rule">
                <SessionCard session={session} onDeleted={loadSessions} />
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </main>
  )
}

function SessionCard({ session, onDeleted }: { session: Session; onDeleted: () => void }) {
  const startedAt = new Date(session.started_ms)
  const endedAt = session.ended_ms ? new Date(session.ended_ms) : null

  return (
    <article className="flex flex-col gap-1 sm:flex-row sm:items-center">
    <Link
      to={`/map/${encodeURIComponent(session.id)}`}
      className="group -mx-3 flex min-w-0 flex-1 flex-col justify-between gap-4 rounded-card px-3 py-5 transition-colors duration-150 hover:bg-paper-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus sm:flex-row sm:items-center"
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-baseline gap-3">
          <h2 className="truncate text-md font-semibold">{session.name || 'Untitled session'}</h2>
          <SessionStatus active={session.active} />
        </div>
        <div className="mt-1 flex flex-wrap gap-x-4 gap-y-1 text-sm text-muted">
          <span>Started {formatDate(startedAt)}</span>
          <span>{session.ephemeral ? `Rolling · last ${session.retention_minutes || 5} minutes` : session.active ? 'Capturing now' : formatDuration(startedAt, endedAt)}</span>
        </div>
        <p className="mt-1 truncate font-outlier text-xs text-faint">{session.id}</p>
      </div>
      <span className="shrink-0 text-sm font-semibold text-accent group-hover:underline">
        Open map
      </span>
    </Link>
    <div className="flex justify-end sm:pl-4"><DeleteSession session={session} onDeleted={onDeleted} /></div>
    </article>
  )
}

function SessionStatus({ active }: { active: boolean }) {
  return active ? (
    <span className="text-xs font-semibold text-down">Live</span>
  ) : (
    <span className="text-xs text-muted">Recorded</span>
  )
}

function SessionsLoading() {
  return (
    <div className="border-t border-rule" aria-label="Loading sessions" aria-live="polite">
      {[0, 1, 2].map((item) => (
        <div key={item} className="flex h-24 flex-col justify-center gap-2 border-b border-rule">
          <div className="h-4 w-56 animate-pulse rounded-card bg-paper-3" />
          <div className="h-3 w-40 animate-pulse rounded-card bg-paper-2" />
        </div>
      ))}
    </div>
  )
}

function formatDate(date: Date | null) {
  return date ? dateFormatter.format(date) : 'Unknown'
}

function formatDuration(start: Date | null, end: Date | null) {
  if (!start || !end) return 'Recorded session'
  const totalMinutes = Math.max(0, Math.round((end.getTime() - start.getTime()) / 60_000))
  const hours = Math.floor(totalMinutes / 60)
  const minutes = totalMinutes % 60
  if (hours === 0) return `${minutes} min recording`
  return `${hours} hr ${minutes} min recording`
}
