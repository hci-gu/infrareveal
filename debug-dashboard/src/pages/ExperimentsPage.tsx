import { ArrowUpRight, FlaskConical, Folder, Radio, RefreshCw, Search } from 'lucide-react'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link } from 'react-router-dom'
import { getSessions, type Session } from '@infrareveal/session-state'
import { formatDateTime, formatDuration, displayTimeZone } from '../views/formatters'
import { useElementSize } from '../shared/ui/useElementSize'
import { usePreference } from '../shared/ui/preferences'
import { CopyButton } from '../shared/ui/CopyButton'
import { auditQuality, filterSessions, sessionDuration, summaryCount, type SessionCategory } from './sessions/sessionSummaries'
import { useSessionSummaries } from './sessions/useSessionSummaries'
import '../shared/ui/desktop.css'

const ROW_HEIGHT = 68
export function ExperimentsPage() {
  const requestScope = useRef<AbortController | null>(null)
  const requestBusy = useRef(false)
  const [sessions, setSessions] = useState<Session[]>([])
  const [status, setStatus] = useState<'loading' | 'ready' | 'offline'>('loading')
  const [error, setError] = useState<string | null>(null)
  const [refresh, setRefresh] = useState(0)
  const [now, setNow] = useState(Date.now)
  const [query, setQuery] = useState('')
  const [category, setCategory] = useState<SessionCategory>('all')
  const [selectedId, setSelectedId] = usePreference('sessions.selection', '')
  const [scrollTop, setScrollTop] = useState(0)
  const { ref: listRef, height: listHeight } = useElementSize<HTMLDivElement>()
  const visible = useMemo(() => filterSessions(sessions, category, query), [sessions, category, query])
  const selected = sessions.find(session => session.id === selectedId) ?? (!selectedId ? sessions[0] : null)
  const start = Math.max(0, Math.min(Math.floor(scrollTop / ROW_HEIGHT) - 3, Math.max(0, visible.length - 1)))
  const end = Math.min(visible.length, start + Math.ceil((listHeight || 700) / ROW_HEIGHT) + 7)
  const shown = visible.slice(start, end)
  const summaries = useSessionSummaries([...shown.map(session => session.id), ...(selected ? [selected.id] : [])], refresh)
  const entry = selected ? summaries[selected.id] : undefined
  const selectedVisible = !selected || visible.some(session => session.id === selected.id)
  useEffect(() => { if (!selectedId && sessions.length) setSelectedId(filterSessions(sessions, 'all', '')[0].id) }, [selectedId, sessions, setSelectedId])
  const load = useCallback(async (providedSignal?: AbortSignal) => {
    const signal = providedSignal || requestScope.current?.signal
    if (!signal || signal.aborted || requestBusy.current) return
    requestBusy.current = true
    try {
      const next = await getSessions(signal)
      if (signal?.aborted) return
      setSessions(next); setStatus('ready'); setError(null); setRefresh(value => value + 1)
    } catch (caught) {
      if (signal?.aborted) return
      setStatus('offline'); setError(caught instanceof Error ? caught.message : 'Unable to load sessions')
    } finally { requestBusy.current = false }
  }, [])
  useEffect(() => {
    const controller = new AbortController(); requestScope.current = controller
    const initial = setTimeout(() => void load(controller.signal), 0)
    const poll = setInterval(() => void load(controller.signal), 5_000)
    const clock = setInterval(() => setNow(Date.now()), 1_000)
    return () => { controller.abort(); clearTimeout(initial); clearInterval(poll); clearInterval(clock) }
  }, [load])
  const resetScroll = () => { listRef.current?.scrollTo({ top: 0 }); setScrollTop(0) }
  const duration = (session: Session) => {
    const summary = summaries[session.id]
    const value = sessionDuration(session, summary?.manifest, summary?.receivedAt, now)
    return value === null ? 'Unknown' : formatDuration(value)
  }
  const count = (session: Session, key: string) => summaryCount(summaries[session.id]?.manifest, key)?.toLocaleString() ?? '—'
  return <main className="desktop-ui sessions-workspace">
    <header className="sessions-heading"><div><div className="app-wordmark">InfraReveal <span>/ session library</span></div><h1>Sessions</h1><p>Select a source, then open the tool you need.</p></div>
      <div className="sessions-heading-actions"><label className="ui-search"><Search size={15} /><input type="search" aria-label="Search sessions" placeholder="Search sessions…" value={query} onChange={event => { setQuery(event.target.value); resetScroll() }} /></label><button type="button" title="Refresh sessions" aria-label="Refresh sessions" onClick={() => void load()}><RefreshCw size={16} /></button></div>
    </header>
    {error ? <div className="ui-notice warning" role="status">Gateway unavailable. {sessions.length ? 'Showing the last loaded sessions. ' : ''}{error}</div> : null}
    <div className="sessions-layout">
      <nav className="session-categories" aria-label="Session categories"><h2>Library</h2>{(['all', 'live', 'recorded'] as const).map(value => <button type="button" key={value} aria-pressed={category === value} onClick={() => { setCategory(value); resetScroll() }}><span>{value === 'live' ? <Radio size={15} /> : <Folder size={15} />}{value === 'all' ? 'All sessions' : value === 'live' ? 'Live' : 'Recordings'}</span><small>{sessions.filter(session => value === 'all' || session.active === (value === 'live')).length}</small></button>)}<div className="session-utilities"><span className={`connection-dot ${status}`} />{status === 'ready' ? 'Gateway connected' : status === 'loading' ? 'Connecting…' : 'Gateway offline'}<Link to="/controlled-client"><FlaskConical size={14} /> Controlled client</Link></div></nav>
      <section className="session-list" aria-label="Session sources"><header><h2>{category === 'all' ? 'All sessions' : category === 'live' ? 'Live sessions' : 'Recordings'}</h2><span>Newest first</span></header>
        <div className="session-list-scroll" ref={listRef} onScroll={event => setScrollTop(event.currentTarget.scrollTop)}>
          <table className="session-table" aria-label="Sessions"><thead><tr><th scope="col">Session</th><th scope="col">Duration</th><th scope="col">Flows</th><th scope="col">Gate audit</th></tr></thead><tbody>
            {start > 0 ? <tr aria-hidden="true" className="spacer-row"><td colSpan={4} style={{ height: start * ROW_HEIGHT }} /></tr> : null}
            {shown.map((session, index) => <tr key={session.id} className={selected?.id === session.id ? 'selected' : ''}><td><button type="button" className="session-name" data-session-id={session.id} aria-pressed={selected?.id === session.id} onClick={() => setSelectedId(session.id)} onKeyDown={event => {
              if (event.key !== 'ArrowUp' && event.key !== 'ArrowDown') return
              event.preventDefault(); const targetIndex = Math.max(0, Math.min(visible.length - 1, start + index + (event.key === 'ArrowDown' ? 1 : -1)))
              const next = visible[targetIndex]; setSelectedId(next.id)
              if (listRef.current && (targetIndex * ROW_HEIGHT < scrollTop || (targetIndex + 1) * ROW_HEIGHT > scrollTop + listHeight - 40)) listRef.current.scrollTo({ top: Math.max(0, targetIndex * ROW_HEIGHT - listHeight / 2) })
              requestAnimationFrame(() => listRef.current?.querySelector<HTMLButtonElement>(`[data-session-id="${CSS.escape(next.id)}"]`)?.focus({ preventScroll: true }))
            }}>{session.name || session.id}</button>{session.active ? <span className="live-label">● LIVE</span> : null}<span className="session-date">{formatDateTime(session.started_at || session.created)}</span></td><td className="numeric">{duration(session)}</td><td className="numeric" title={summaries[session.id]?.error || 'Session flow records'}>{count(session, 'flows')}</td><td><span className={`audit-label ${auditQuality(session, summaries[session.id]?.manifest).toLowerCase()}`}>{auditQuality(session, summaries[session.id]?.manifest)}</span></td></tr>)}
            {end < visible.length ? <tr aria-hidden="true" className="spacer-row"><td colSpan={4} style={{ height: (visible.length - end) * ROW_HEIGHT }} /></tr> : null}
          </tbody></table>
          {visible.length === 0 ? <div className="ui-empty"><Folder size={25} /><h3>{status === 'loading' ? 'Loading sessions…' : sessions.length ? 'No matching sessions' : 'No sessions available'}</h3><p>{sessions.length ? 'Clear the search or choose another category.' : 'Start a gateway session, then refresh this library.'}</p></div> : null}
        </div>
      </section>
      <aside className="session-details" aria-label="Selected session">
        {selected ? <><div className="source-icon"><Folder size={24} /></div><span className="source-kind">{selected.active ? '● Live session' : 'Recorded session'}</span><h2>{selected.name || selected.id}</h2><div className="source-id">{selected.id}<CopyButton label="Copy session ID" value={selected.id} /></div>
          {!selectedVisible ? <p className="ui-notice">Selected source is outside the current filter.</p> : null}
          <dl><dt>Started</dt><dd>{formatDateTime(selected.started_at || selected.created)}</dd><dt>{selected.active ? 'Elapsed' : 'Duration'}</dt><dd>{duration(selected)}</dd><dt>Flow records</dt><dd>{count(selected, 'flows')}</dd><dt>DNS records</dt><dd>{count(selected, 'dns_queries')}</dd><dt>Gate audit</dt><dd>{auditQuality(selected, entry?.manifest)}{(entry?.manifest?.gateAuditDrops ?? selected.gate_audit_drops ?? 0) > 0 ? ` · ${entry?.manifest?.gateAuditDrops ?? selected.gate_audit_drops} lost` : ''}</dd></dl>
          {entry?.error ? <p className="ui-notice warning">Summary unavailable. {entry.error}</p> : !entry?.manifest ? <p className="muted" role="status">Loading session summary…</p> : null}
          <div className="source-launch"><Link className="ui-primary" to={`/timeline/${encodeURIComponent(selected.id)}`}>Open Traffic <ArrowUpRight size={16} /></Link><Link to={`/proxy-lab/${encodeURIComponent(selected.id)}`}>Open Lab <ArrowUpRight size={16} /></Link></div><p className="muted">Traffic explores the recording in time. Lab follows its path through gateway nodes.</p>
          <details className="session-metadata"><summary>Source metadata</summary><CopyButton label="Copy session metadata" value={JSON.stringify({ session: selected, manifest: entry?.manifest }, null, 2)} /><pre>{JSON.stringify({ session: selected, manifest: entry?.manifest }, null, 2)}</pre></details>
        </> : <div className="ui-empty"><h3>{selectedId ? 'Source no longer available' : 'Choose a session'}</h3><p>{selectedId ? 'Select another source from the library.' : 'Its details and tool launch actions will appear here.'}</p></div>}
      </aside>
    </div>
    <footer className="desktop-status"><span>{visible.length} of {sessions.length} sessions</span><span>Session summaries load on demand · {displayTimeZone}</span></footer>
  </main>
}
