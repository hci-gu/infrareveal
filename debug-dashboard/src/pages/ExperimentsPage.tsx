import { Activity, ArrowRight, FlaskConical, Network, Radio, RefreshCw } from 'lucide-react'
import { useCallback, useEffect, useMemo, useState } from 'react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import { getSessions } from '@infrareveal/session-state'
import type { Session } from '@infrareveal/session-state'
import { formatDateTime } from '../views/formatters'
import { partitionSessions } from './sessionGroups'

const SESSION_REFRESH_MS = 5_000

export function ExperimentsPage() {
  const [sessions, setSessions] = useState<Session[]>([])
  const [status, setStatus] = useState<'loading' | 'ready' | 'offline'>('loading')
  const [error, setError] = useState<string | null>(null)
  const grouped = useMemo(() => partitionSessions(sessions), [sessions])

  const loadSessions = useCallback(async (signal?: AbortSignal) => {
    try {
      const next = await getSessions(signal)
      setSessions(next)
      setStatus('ready')
      setError(null)
    } catch (loadError) {
      if (signal?.aborted) return
      setStatus('offline')
      setError(loadError instanceof Error ? loadError.message : 'Unable to load sessions.')
    }
  }, [])

  useEffect(() => {
    const controller = new AbortController()
    const initialTimer = window.setTimeout(() => void loadSessions(controller.signal), 0)
    const refreshTimer = window.setInterval(() => void loadSessions(controller.signal), SESSION_REFRESH_MS)
    return () => {
      controller.abort()
      window.clearTimeout(initialTimer)
      window.clearInterval(refreshTimer)
    }
  }, [loadSessions])

  return (
    <main className="min-h-screen bg-slate-950 text-slate-100">
      <header className="border-b border-slate-800 bg-slate-950/95">
        <div className="mx-auto flex max-w-7xl flex-col gap-5 px-5 py-7 md:flex-row md:items-end md:justify-between">
          <div>
            <p className="text-xs font-semibold uppercase tracking-[0.2em] text-cyan-400">InfraReveal debug lab</p>
            <h1 className="mt-2 text-4xl font-semibold tracking-tight">Choose an experiment</h1>
            <p className="mt-2 max-w-2xl text-sm leading-6 text-slate-400">
              Inspect one shared session clock through the production timeline model or the proxy pipeline teaching view.
            </p>
          </div>
          <button
            className="inline-flex h-10 items-center justify-center gap-2 border border-slate-700 bg-slate-900 px-4 text-sm font-semibold hover:border-cyan-500 hover:text-cyan-300"
            onClick={() => void loadSessions()}
            type="button"
          >
            <RefreshCw size={16} /> Refresh
          </button>
        </div>
      </header>

      <section className="mx-auto max-w-7xl space-y-9 px-5 py-8">
        <Link className="flex items-center justify-between border border-violet-800 bg-violet-950/20 p-4 text-sm font-semibold text-violet-200 hover:border-violet-500" to="/controlled-client"><span className="flex items-center gap-3"><FlaskConical size={18} /> Open controlled network timeout client</span><ArrowRight size={16} /></Link>
        {status === 'loading' ? <StatusPanel title="Loading sessions" detail="Connecting to the gateway timeline API…" /> : null}
        {error ? <StatusPanel tone="error" title="Gateway unavailable" detail={error} /> : null}
        {status === 'ready' && sessions.length === 0 ? (
          <StatusPanel title="No sessions yet" detail="Start a gateway session; this page will discover it automatically." />
        ) : null}

        {grouped.active.length > 0 ? (
          <SessionGroup icon={<Radio size={18} />} label="Active sessions" sessions={grouped.active} />
        ) : null}
        {grouped.recorded.length > 0 ? (
          <SessionGroup icon={<Activity size={18} />} label="Recorded sessions" sessions={grouped.recorded} />
        ) : null}
      </section>
    </main>
  )
}

function SessionGroup({ icon, label, sessions }: { icon: ReactNode; label: string; sessions: Session[] }) {
  return (
    <section>
      <div className="mb-4 flex items-center gap-2 text-sm font-semibold uppercase tracking-[0.14em] text-slate-400">
        {icon} {label} <span className="text-slate-600">{sessions.length}</span>
      </div>
      <div className="grid gap-4 lg:grid-cols-2">
        {sessions.map((session) => <SessionCard key={session.id} session={session} />)}
      </div>
    </section>
  )
}

function SessionCard({ session }: { session: Session }) {
  const title = session.name || `Session ${session.id.slice(0, 8)}`
  const timestamp = session.started_at || session.created
  return (
    <article className="border border-slate-800 bg-slate-900/80 p-5 shadow-2xl shadow-black/10">
      <div className="flex items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            {session.active ? <span className="h-2 w-2 rounded-full bg-emerald-400 shadow-[0_0_12px_#34d399]" /> : null}
            <h2 className="truncate text-xl font-semibold">{title}</h2>
          </div>
          <p className="mt-1 font-mono text-xs text-slate-500">{session.id}</p>
          <p className="mt-3 text-sm text-slate-400">{formatDateTime(timestamp)}</p>
          {session.gate_audit_complete === false ? <p className="mt-2 text-xs font-semibold text-rose-300">Gate audit incomplete · {session.gate_audit_drops ?? 0} lost</p> : null}
        </div>
        <span className={`border px-2 py-1 text-xs font-semibold uppercase tracking-wider ${session.active ? 'border-emerald-800 bg-emerald-950 text-emerald-300' : 'border-slate-700 text-slate-400'}`}>
          {session.active ? 'Live' : 'Recorded'}
        </span>
      </div>
      <div className="mt-6 grid gap-2 sm:grid-cols-2">
        <ExperimentLink icon={<Activity size={17} />} label="Session timeline" to={`/timeline/${session.id}`} />
        <ExperimentLink icon={<Network size={17} />} label="Proxy pipeline" to={`/proxy-lab/${session.id}`} />
      </div>
    </article>
  )
}

function ExperimentLink({ icon, label, to }: { icon: ReactNode; label: string; to: string }) {
  return (
    <Link className="group flex items-center justify-between border border-slate-700 bg-slate-950 px-3 py-3 text-sm font-semibold hover:border-cyan-500 hover:text-cyan-300" to={to}>
      <span className="flex items-center gap-2">{icon}{label}</span>
      <ArrowRight className="transition-transform group-hover:translate-x-1" size={16} />
    </Link>
  )
}

function StatusPanel({ detail, title, tone = 'neutral' }: { detail: string; title: string; tone?: 'neutral' | 'error' }) {
  return (
    <div className={`border px-5 py-8 ${tone === 'error' ? 'border-red-900 bg-red-950/40 text-red-100' : 'border-slate-800 bg-slate-900/70'}`}>
      <h2 className="text-lg font-semibold">{title}</h2>
      <p className="mt-2 text-sm text-slate-400">{detail}</p>
    </div>
  )
}
