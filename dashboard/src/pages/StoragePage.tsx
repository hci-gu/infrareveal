import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useSessions } from '@infrareveal/session-state'
import { DeleteSession } from '../maintenance/DeleteSession'
import { maintenanceRequest, storageBytes } from '../maintenance/client'
import type { GeoIPStatus, StorageStatus } from '../maintenance/client'

const button = 'h-9 whitespace-nowrap rounded-card border border-field-edge bg-transparent px-4 text-sm font-semibold text-ink hover:bg-paper-3 active:bg-paper-2 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:text-faint disabled:opacity-60'
const card = 'rounded-panel border border-rule bg-paper-2 p-6'
const date = (ms: number) => ms ? new Date(ms).toLocaleString('en-GB') : 'Unavailable'

export function StoragePage() {
  const [storage, setStorage] = useState<StorageStatus | null>(null)
  const [error, setError] = useState('')
  const [busy, setBusy] = useState(false)
  const { sessions, status, error: sessionError, refresh } = useSessions()
  const load = useCallback(async (signal?: AbortSignal) => {
    setBusy(true); setError('')
    try { const value = await maintenanceRequest<StorageStatus>('storage', 'GET', undefined, signal); if (!signal?.aborted) setStorage(value) }
    catch (e) { if (!signal?.aborted) setError(e instanceof Error ? e.message : 'Cannot read storage') }
    finally { if (!signal?.aborted) setBusy(false) }
  }, [])
  useEffect(() => { const c = new AbortController(); const t = setTimeout(() => void load(c.signal), 0); return () => { clearTimeout(t); c.abort() } }, [load])
  const disk = storage?.disk
  const usedPercent = disk?.total_bytes ? Math.round(100 * disk.used_bytes / disk.total_bytes) : 0
  const states = { ok: 'Space available', low: 'Low disk space', critical: 'Disk nearly full', read_only: 'Disk is read-only', unknown: 'Disk status unavailable' }
  return <main className="min-h-dvh bg-paper px-4 py-10 text-ink sm:px-8">
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div><Link to="/" className="rounded-card text-sm font-semibold text-accent hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus">Sessions</Link><h1 className="mt-3 text-2xl font-semibold tracking-tight">Storage & maintenance</h1><p className="mt-3 text-muted">Check gateway storage, remove recordings and update location data.</p></div>
        <button type="button" className={button} disabled={busy} onClick={() => { void load(); refresh() }}>{busy ? 'Checking…' : 'Refresh storage'}</button>
      </header>
      {error && <p role="alert" className="rounded-panel bg-error-paper p-4 text-error">{error}</p>}
      {!storage && !error && <p role="status">Reading gateway storage…</p>}
      {disk && <section className={card} aria-label="Gateway disk status">
        <div className="flex flex-wrap justify-between gap-3"><h2 className="text-lg font-semibold">Gateway disk</h2><span className={`text-sm font-semibold ${disk.state === 'ok' ? 'text-success' : 'text-warn'}`}>{states[disk.state]}</span></div>
        <div className="mt-5 grid gap-5 sm:grid-cols-3"><Metric label="Available" value={storageBytes(disk.available_bytes)} /><Metric label="Used" value={`${storageBytes(disk.used_bytes)} · ${usedPercent}%`} /><Metric label="Total capacity" value={storageBytes(disk.total_bytes)} /></div>
        <progress aria-label="Disk space used" max={100} value={usedPercent} className="mt-5 h-3 w-full accent-accent" />
        <p className="mt-3 text-sm text-muted">Includes the operating system, Docker images, logs and recordings. SD-card wear and remaining hardware lifespan are not reported by this device.</p>
        {disk.state !== 'ok' && <p className="mt-3 text-sm font-semibold text-warn">{disk.read_only ? 'Storage is read-only. Recording and updates may fail.' : 'Storage is running low. Deleting recordings makes database space reusable; system logs and deployment files also use disk space.'}</p>}
        <p className="mt-3 text-xs text-muted">Checked {date(storage!.checked_ms)}</p>
      </section>}
      {storage && <section className={card} aria-label="Application storage"><h2 className="text-lg font-semibold">Application storage</h2><div className="mt-4 grid gap-4 sm:grid-cols-2">{storage.databases.map(db => <div key={db.name} className="border-t border-rule pt-4"><h3 className="font-semibold">{db.name === 'data.db' ? 'Recordings' : 'Application logs'}</h3><p className="mt-2 font-outlier text-xl tabular-nums">{storageBytes(db.bytes + db.wal_bytes)}</p><p className="mt-2 text-sm text-muted">Database {storageBytes(db.bytes)} · write journal {storageBytes(db.wal_bytes)}</p><p className="mt-1 text-sm text-muted">{storageBytes(db.reusable_bytes)} reusable inside the database</p></div>)}</div><p className="mt-4 text-sm text-muted">SQLite reuses deleted space. File sizes may remain stable after deleting a session.</p>{storage.maintenance.lastError && <p className="mt-3 text-sm text-error" role="alert">Recording maintenance: {storage.maintenance.lastError}</p>}</section>}
      <GeoIPPanel />
      <section className={card} aria-label="Manage recordings"><h2 className="text-lg font-semibold">Manage recordings</h2><p className="mt-2 text-sm text-muted">Choose individual sessions to remove. Existing rolling retention is unchanged.</p>
        {status === 'loading' && <p className="mt-4">Loading sessions…</p>}
        {sessionError && <p className="mt-4 text-error" role="alert">{sessionError}</p>}
        {status === 'ready' && sessions.length === 0 && <p className="mt-4">No recordings stored.</p>}
        <ul className="mt-4 divide-y divide-rule">{sessions.map(session => <li key={session.id} className="flex flex-wrap items-center justify-between gap-4 py-4"><div><Link to={`/map/${encodeURIComponent(session.id)}`} className="rounded-card font-semibold text-accent hover:underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus">{session.name || 'Untitled session'}</Link><p className="mt-1 text-sm text-muted">{session.active ? 'Live' : 'Recorded'} · {session.ephemeral ? `${session.retention_minutes} minute rolling window` : 'Saved history'}{storage && ` · ${(storage.session_counts?.find(s => s.session === session.id)?.chunks || 0).toLocaleString()} traffic records`}</p></div><DeleteSession session={session} onDeleted={() => { refresh(); void load() }} /></li>)}</ul>
      </section>
    </div>
  </main>
}

function Metric({ label, value }: { label: string; value: string }) { return <div><p className="text-sm text-muted">{label}</p><p className="mt-1 font-outlier text-xl tabular-nums">{value}</p></div> }

export function GeoIPPanel() {
  const [geo, setGeo] = useState<GeoIPStatus | null>(null)
  const [error, setError] = useState('')
  const [account, setAccount] = useState('')
  const [key, setKey] = useState('')
  const [editing, setEditing] = useState(false)
  const [busy, setBusy] = useState(false)
  const [retry, setRetry] = useState(0)
  useEffect(() => {
    const c = new AbortController()
    let timer: ReturnType<typeof setTimeout>
    const read = async () => {
      try {
        const s = await maintenanceRequest<GeoIPStatus>('geoip', 'GET', undefined, c.signal)
        if (c.signal.aborted) return
        setGeo(s); setError('')
        if (s.phase === 'downloading' || s.phase === 'validating') timer = setTimeout(() => void read(), 1500)
      } catch (e) { if (!c.signal.aborted) setError(e instanceof Error ? e.message : 'Cannot read GeoIP status') }
    }
    timer = setTimeout(() => void read(), 0)
    return () => { clearTimeout(timer); c.abort() }
  }, [retry])
  const working = busy || geo?.phase === 'downloading' || geo?.phase === 'validating'
  const save = async (event: React.FormEvent) => {
    event.preventDefault(); setBusy(true); setError('')
    try { setGeo(await maintenanceRequest<GeoIPStatus>('geoip/settings', 'PUT', { account_id: account, license_key: key })); setKey(''); setEditing(false) }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not save MaxMind settings') }
    finally { setBusy(false) }
  }
  const update = async () => {
    setBusy(true); setError('')
    try { setGeo(await maintenanceRequest<GeoIPStatus>('geoip/refresh', 'POST')); setRetry(n => n + 1) }
    catch (e) { setError(e instanceof Error ? e.message : 'Could not start GeoIP refresh') }
    finally { setBusy(false) }
  }
  return <section className={card} aria-label="GeoIP database">
    <h2 className="text-lg font-semibold">GeoIP database</h2><p className="mt-2 text-sm text-muted">MaxMind GeoLite2 City supplies approximate destination locations. GeoLite2 ASN names the network that owns an address when no DNS lookup identifies the service.</p>
    {geo && <><div className="mt-5 grid gap-5 sm:grid-cols-3"><Metric label="Installed database" value={geo.available ? geo.database_type : 'Not installed'} /><Metric label="Database built" value={geo.build_ms ? new Date(geo.build_ms).toLocaleDateString('en-GB') : 'Unavailable'} /><Metric label="File size" value={storageBytes(geo.bytes)} /></div>
      <p className="mt-3 text-sm text-ink-2">Network owners (ASN): {geo.asn_available ? `installed · built ${new Date(geo.asn_build_ms ?? 0).toLocaleDateString('en-GB')} · ${storageBytes(geo.asn_bytes ?? 0)}` : 'not installed — the next refresh downloads it'}</p>
      <p className="mt-4 text-sm text-muted">Refresh downloads and checks a replacement before switching files. Saved observations keep their original locations.</p>
      {(geo.phase !== 'idle' || geo.message) && <p role="status" className="mt-4 text-sm font-semibold">{geo.error || geo.message}{geo.phase === 'downloading' ? ` · ${storageBytes(geo.downloaded_bytes)} downloaded` : ''}</p>}
      {!geo.configured && <p className="mt-4 border-l-2 border-accent pl-3 text-sm text-ink-2">Add your MaxMind account ID and license key to enable manual updates.</p>}
      <div className="mt-5 flex flex-wrap gap-3"><button type="button" className="h-9 whitespace-nowrap rounded-card bg-accent px-4 text-sm font-semibold text-accent-ink hover:brightness-110 active:brightness-95 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus disabled:cursor-not-allowed disabled:opacity-60" disabled={!geo.configured || working} onClick={() => void update()}>{working ? 'Refresh in progress…' : 'Refresh GeoIP database'}</button><button type="button" className={button} disabled={working} onClick={() => { setAccount(geo.account_id); setKey(''); setEditing(!editing) }}>{editing ? 'Close settings' : 'MaxMind settings'}</button></div>
    </>}
    {error && <div className="mt-4 text-sm text-error" role="alert">{error} <button type="button" className="font-semibold underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus" onClick={() => setRetry(n => n + 1)}>Check status again</button></div>}
    {!geo && !error && <p className="mt-4">Reading database information…</p>}
    {editing && <form onSubmit={event => void save(event)} className="mt-5 space-y-4 border-t border-rule pt-5">
      <label className="block text-sm font-semibold">MaxMind account ID<input required inputMode="numeric" autoComplete="off" value={account} onChange={e => setAccount(e.target.value)} className="mt-1 block h-9 w-full rounded-card border border-field-edge bg-paper px-2 font-normal text-ink focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-focus" /></label>
      <label className="block text-sm font-semibold">License key<input type="password" autoComplete="new-password" required={!geo?.configured || account !== geo.account_id} value={key} onChange={e => setKey(e.target.value)} placeholder={geo?.configured ? 'Leave blank to keep the saved key' : ''} className="mt-1 block h-9 w-full rounded-card border border-field-edge bg-paper px-2 font-normal text-ink focus-visible:outline-2 focus-visible:-outline-offset-1 focus-visible:outline-focus" /></label>
      <p className="text-sm text-muted">Saved on the gateway. The saved key is never sent back to the dashboard. <a href="https://www.maxmind.com/en/accounts/current/license-key" target="_blank" rel="noreferrer" className="text-accent underline focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-focus">Manage MaxMind license keys</a>.</p>
      <button type="submit" className={button} disabled={working}>{busy ? 'Saving…' : 'Save MaxMind settings'}</button>
    </form>}
  </section>
}
