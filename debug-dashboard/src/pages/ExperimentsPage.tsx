import { useState } from 'react'
import { Link } from 'react-router-dom'
import { updateSession, useSessions } from '@infrareveal/session-state'
import '../shared/ui/desktop.css'
import '../experiments/session-playback/activity.css'
export function ExperimentsPage() {
  const { sessions, status, error, refresh } = useSessions(5000)
  const [query, setQuery] = useState(''), [name, setName] = useState(''), [message, setMessage] = useState('')
  const visible = sessions.filter(session => `${session.name} ${session.id}`.toLowerCase().includes(query.toLowerCase()))
  const act = async (id: string, method: 'POST' | 'PATCH' | 'DELETE', value?: Record<string, unknown>, action = '') => {
    try { await updateSession(id, method, value, action); setMessage(''); refresh() } catch (error) { setMessage(error instanceof Error ? error.message : 'Operation failed') }
  }
  return <main className="desktop-ui sessions-workspace"><header className="sessions-heading"><div><div className="app-wordmark">InfraReveal / activity library</div><h1>Sessions</h1><p>Explore service activity blocks, captured traffic, and optional diagnostics.</p></div><Link to="/controlled-client">Controlled client</Link></header>
    <section className="activity-library-tools"><input aria-label="Search sessions" placeholder="Search sessions…" value={query} onChange={event => setQuery(event.target.value)} /><button onClick={refresh}>Refresh</button><form onSubmit={event => { event.preventDefault(); if (name.trim()) void act('', 'POST', { name: name.trim() }) }}><input aria-label="New session name" placeholder="New session name" value={name} onChange={event => setName(event.target.value)} /><button disabled={!name.trim()}>Start session</button></form></section>
    {(error || message) && <p role="status" className="ui-notice warning">{message || error}</p>}
    <div className="session-list-scroll"><table className="session-table"><thead><tr><th>Session</th><th>Started</th><th>Capture</th><th>History</th><th>Open</th></tr></thead><tbody>{visible.map(session => <tr key={session.id}><td><strong>{session.name}</strong>{session.active && <span className="live-label">LIVE</span>}<small className="session-date">{session.id}</small></td><td>{new Date(session.started_ms).toLocaleString()}</td><td>{session.capture.quality}{session.capture.error && <small>{session.capture.error}</small>}</td><td>{session.ephemeral ? `Last ${session.retention_minutes || 5} minutes` : session.active ? 'Recording' : 'Saved'}</td><td><Link to={`/timeline/${session.id}`}>Activity</Link> · <Link to={`/proxy-lab/${session.id}`}>Lab</Link>{session.active && <button onClick={() => void act(session.id, 'POST', undefined, 'end')}>End</button>}</td></tr>)}</tbody></table>{!visible.length && <p>{status === 'loading' ? 'Loading sessions…' : 'No matching sessions.'}</p>}</div>
    <footer className="desktop-status"><span>{visible.length} sessions · {status}</span><span>Capture quality and traffic totals come from captured packets.</span></footer>
  </main>
}
