import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { getSessions } from '@infrareveal/session-state'
import type { Session } from '@infrareveal/session-state'

type LoadStatus = 'loading' | 'ready' | 'error'

const dateFormatter = new Intl.DateTimeFormat('en-GB', {
  dateStyle: 'medium',
  timeStyle: 'short',
})

export function SessionsPage() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [status, setStatus] = useState<LoadStatus>('loading')
  const [error, setError] = useState('')

  const loadSessions = useCallback(async () => {
    setStatus('loading')
    setError('')
    try {
      setSessions(await getSessions())
      setStatus('ready')
    } catch (reason) {
      setError(reason instanceof Error ? reason.message : 'Unable to load sessions')
      setStatus('error')
    }
  }, [])

  useEffect(() => {
    let cancelled = false
    getSessions()
      .then((nextSessions) => {
        if (cancelled) return
        setSessions(nextSessions)
        setStatus('ready')
      })
      .catch((reason: unknown) => {
        if (cancelled) return
        setError(reason instanceof Error ? reason.message : 'Unable to load sessions')
        setStatus('error')
      })
    return () => {
      cancelled = true
    }
  }, [])

  const activeCount = sessions.filter((session) => session.active).length

  return (
    <main className="min-h-screen bg-slate-100 px-5 py-10 text-slate-950 sm:px-8 lg:px-12">
      <section className="mx-auto max-w-5xl">
        <header className="mb-8 flex flex-col justify-between gap-4 sm:flex-row sm:items-end">
          <div>
            <p className="mb-2 text-sm font-bold uppercase tracking-[0.2em] text-blue-700">
              InfraReveal
            </p>
            <h1 className="text-4xl font-black tracking-tight sm:text-5xl">Sessions</h1>
            <p className="mt-3 max-w-2xl text-base text-slate-600">
              Open a recorded session or follow an active session on the shared timeline map.
            </p>
          </div>
          {status === 'ready' && sessions.length > 0 ? (
            <div className="flex gap-2 text-sm font-semibold">
              <span className="rounded-full bg-white px-3 py-1.5 shadow-sm">
                {sessions.length} total
              </span>
              <span className="rounded-full bg-emerald-100 px-3 py-1.5 text-emerald-800">
                {activeCount} live
              </span>
            </div>
          ) : null}
        </header>

        {status === 'loading' ? <SessionsLoading /> : null}
        {status === 'error' ? (
          <div className="rounded-2xl border border-red-200 bg-white p-8 shadow-sm">
            <h2 className="text-lg font-bold text-red-800">Could not load sessions</h2>
            <p className="mt-2 text-sm text-slate-600">{error}</p>
            <button
              type="button"
              onClick={() => void loadSessions()}
              className="mt-5 rounded-lg bg-slate-950 px-4 py-2 text-sm font-bold text-white hover:bg-slate-800"
            >
              Retry
            </button>
          </div>
        ) : null}
        {status === 'ready' && sessions.length === 0 ? (
          <div className="rounded-2xl border border-dashed border-slate-300 bg-white p-12 text-center">
            <h2 className="text-xl font-bold">No sessions yet</h2>
            <p className="mt-2 text-sm text-slate-600">
              Sessions will appear here once capture has started.
            </p>
          </div>
        ) : null}
        {status === 'ready' && sessions.length > 0 ? (
          <ul className="grid gap-4">
            {sessions.map((session) => (
              <li key={session.id}>
                <SessionCard session={session} />
              </li>
            ))}
          </ul>
        ) : null}
      </section>
    </main>
  )
}

function SessionCard({ session }: { session: Session }) {
  const startedAt = parseDate(session.started_at ?? session.created)
  const endedAt = session.ended_at ? parseDate(session.ended_at) : null

  return (
    <Link
      to={`/map/${encodeURIComponent(session.id)}`}
      className="group flex flex-col justify-between gap-5 rounded-2xl border border-slate-200 bg-white p-5 shadow-sm transition hover:-translate-y-0.5 hover:border-blue-300 hover:shadow-md focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-blue-600 sm:flex-row sm:items-center"
    >
      <div className="min-w-0">
        <div className="flex flex-wrap items-center gap-2">
          <h2 className="truncate text-lg font-extrabold">{session.name || 'Untitled session'}</h2>
          <SessionStatus active={session.active} />
        </div>
        <div className="mt-2 flex flex-wrap gap-x-4 gap-y-1 text-sm text-slate-600">
          <span>Started {formatDate(startedAt)}</span>
          <span>{session.active ? 'Capturing now' : formatDuration(startedAt, endedAt)}</span>
        </div>
        <p className="mt-2 truncate font-mono text-xs text-slate-400">{session.id}</p>
      </div>
      <span className="shrink-0 text-sm font-bold text-blue-700 transition group-hover:translate-x-0.5">
        Open map →
      </span>
    </Link>
  )
}

function SessionStatus({ active }: { active: boolean }) {
  return active ? (
    <span className="inline-flex items-center gap-1.5 rounded-full bg-emerald-100 px-2.5 py-1 text-xs font-bold text-emerald-800">
      <span className="h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
      Live
    </span>
  ) : (
    <span className="rounded-full bg-slate-100 px-2.5 py-1 text-xs font-bold text-slate-600">
      Recorded
    </span>
  )
}

function SessionsLoading() {
  return (
    <div className="grid gap-4" aria-label="Loading sessions" aria-live="polite">
      {[0, 1, 2].map((item) => (
        <div key={item} className="h-28 animate-pulse rounded-2xl border border-slate-200 bg-white" />
      ))}
    </div>
  )
}

function parseDate(value: string) {
  const normalized = value.includes('T') ? value : value.replace(' ', 'T')
  const date = new Date(normalized)
  return Number.isNaN(date.getTime()) ? null : date
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
