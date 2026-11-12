import { useCallback, useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
import { useSessions } from '@infrareveal/session-state'
import { DeleteSession } from '../maintenance/DeleteSession'
import { maintenanceRequest, storageBytes } from '../maintenance/client'
import type { GeoIPStatus, StorageStatus } from '../maintenance/client'

const button = 'rounded-lg border border-slate-300 bg-white px-4 py-2 text-sm font-bold hover:bg-slate-50 disabled:opacity-50'
const card = 'rounded-2xl border border-slate-200 bg-white p-6 shadow-sm'
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
  return <main className="min-h-screen bg-slate-100 px-5 py-10 text-slate-950 sm:px-8">
    <div className="mx-auto max-w-5xl space-y-6">
      <header className="flex flex-wrap items-end justify-between gap-4">
        <div><Link to="/" className="text-sm font-bold text-blue-700">← Sessions</Link><h1 className="mt-3 text-4xl font-black tracking-tight">Storage & maintenance</h1><p className="mt-3 text-slate-600">Check gateway storage, remove recordings and update location data.</p></div>
        <button type="button" className={button} disabled={busy} onClick={() => { void load(); refresh() }}>{busy ? 'Checking…' : 'Refresh storage'}</button>
      </header>
      {error && <p role="alert" className="rounded-xl bg-red-50 p-4 text-red-800">{error}</p>}
      {!storage && !error && <p role="status">Reading gateway storage…</p>}
      {disk && <section className={card} aria-label="Gateway disk status">
        <div className="flex flex-wrap justify-between gap-3"><h2 className="text-xl font-bold">Gateway disk</h2><span className={`rounded-full px-3 py-1 text-sm font-bold ${disk.state === 'ok' ? 'bg-emerald-100 text-emerald-800' : 'bg-amber-100 text-amber-900'}`}>{states[disk.state]}</span></div>
        <div className="mt-5 grid gap-5 sm:grid-cols-3"><Metric label="Available" value={storageBytes(disk.available_bytes)} /><Metric label="Used" value={`${storageBytes(disk.used_bytes)} · ${usedPercent}%`} /><Metric label="Total capacity" value={storageBytes(disk.total_bytes)} /></div>
        <progress aria-label="Disk space used" max={100} value={usedPercent} className="mt-5 h-3 w-full accent-blue-700" />
        <p className="mt-3 text-sm text-slate-600">Includes the operating system, Docker images, logs and recordings. SD-card wear and remaining hardware lifespan are not reported by this device.</p>
        {disk.state !== 'ok' && <p className="mt-3 text-sm font-semibold text-amber-900">{disk.read_only ? 'Storage is read-only. Recording and updates may fail.' : 'Storage is running low. Deleting recordings makes database space reusable; system logs and deployment files also use disk space.'}</p>}
        <p className="mt-3 text-xs text-slate-500">Checked {date(storage!.checked_ms)}</p>
      </section>}
      {storage && <section className={card} aria-label="Application storage"><h2 className="text-xl font-bold">Application storage</h2><div className="mt-4 grid gap-4 sm:grid-cols-2">{storage.databases.map(db => <div key={db.name} className="rounded-xl bg-slate-50 p-4"><h3 className="font-bold">{db.name === 'data.db' ? 'Recordings' : 'Application logs'}</h3><p className="mt-2 text-2xl font-extrabold">{storageBytes(db.bytes + db.wal_bytes)}</p><p className="mt-2 text-sm text-slate-600">Database {storageBytes(db.bytes)} · write journal {storageBytes(db.wal_bytes)}</p><p className="mt-1 text-sm text-slate-600">{storageBytes(db.reusable_bytes)} reusable inside the database</p></div>)}</div><p className="mt-4 text-sm text-slate-600">SQLite reuses deleted space. File sizes may remain stable after deleting a session.</p>{storage.maintenance.lastError && <p className="mt-3 text-sm text-red-700" role="alert">Recording maintenance: {storage.maintenance.lastError}</p>}</section>}
      <GeoIPPanel />
      <section className={card} aria-label="Manage recordings"><h2 className="text-xl font-bold">Manage recordings</h2><p className="mt-2 text-sm text-slate-600">Choose individual sessions to remove. Existing rolling retention is unchanged.</p>
        {status === 'loading' && <p className="mt-4">Loading sessions…</p>}
        {sessionError && <p className="mt-4 text-red-700" role="alert">{sessionError}</p>}
        {status === 'ready' && sessions.length === 0 && <p className="mt-4">No recordings stored.</p>}
        <ul className="mt-4 divide-y divide-slate-200">{sessions.map(session => <li key={session.id} className="flex flex-wrap items-center justify-between gap-4 py-4"><div><Link to={`/map/${encodeURIComponent(session.id)}`} className="font-bold text-blue-700">{session.name || 'Untitled session'}</Link><p className="mt-1 text-sm text-slate-600">{session.active ? 'Live' : 'Recorded'} · {session.ephemeral ? `${session.retention_minutes} minute rolling window` : 'Saved history'}{storage && ` · ${(storage.session_counts?.find(s => s.session === session.id)?.chunks || 0).toLocaleString()} traffic records`}</p></div><DeleteSession session={session} onDeleted={() => { refresh(); void load() }} /></li>)}</ul>
      </section>
    </div>
  </main>
}

function Metric({ label, value }: { label: string; value: string }) { return <div><p className="text-sm text-slate-500">{label}</p><p className="mt-1 text-2xl font-extrabold">{value}</p></div> }

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
    <h2 className="text-xl font-bold">GeoIP database</h2><p className="mt-2 text-sm text-slate-600">MaxMind GeoLite2 City supplies approximate destination locations.</p>
    {geo && <><div className="mt-5 grid gap-5 sm:grid-cols-3"><Metric label="Installed database" value={geo.available ? geo.database_type : 'Not installed'} /><Metric label="Database built" value={geo.build_ms ? new Date(geo.build_ms).toLocaleDateString('en-GB') : 'Unavailable'} /><Metric label="File size" value={storageBytes(geo.bytes)} /></div>
      <p className="mt-4 text-sm text-slate-600">Refresh downloads and checks a replacement before switching files. Saved observations keep their original locations.</p>
      {(geo.phase !== 'idle' || geo.message) && <p role="status" className="mt-4 text-sm font-semibold">{geo.error || geo.message}{geo.phase === 'downloading' ? ` · ${storageBytes(geo.downloaded_bytes)} downloaded` : ''}</p>}
      {!geo.configured && <p className="mt-4 rounded-lg bg-blue-50 p-3 text-sm text-blue-900">Add your MaxMind account ID and license key to enable manual updates.</p>}
      <div className="mt-5 flex flex-wrap gap-3"><button type="button" className="rounded-lg bg-blue-700 px-4 py-2 text-sm font-bold text-white disabled:opacity-50" disabled={!geo.configured || working} onClick={() => void update()}>{working ? 'Refresh in progress…' : 'Refresh GeoIP database'}</button><button type="button" className={button} disabled={working} onClick={() => { setAccount(geo.account_id); setKey(''); setEditing(!editing) }}>{editing ? 'Close settings' : 'MaxMind settings'}</button></div>
    </>}
    {error && <div className="mt-4 text-sm text-red-700" role="alert">{error} <button type="button" className="font-bold underline" onClick={() => setRetry(n => n + 1)}>Check status again</button></div>}
    {!geo && !error && <p className="mt-4">Reading database information…</p>}
    {editing && <form onSubmit={event => void save(event)} className="mt-5 space-y-4 rounded-xl bg-slate-50 p-4">
      <label className="block text-sm font-bold">MaxMind account ID<input required inputMode="numeric" autoComplete="off" value={account} onChange={e => setAccount(e.target.value)} className="mt-1 block w-full rounded-lg border border-slate-300 bg-white p-2" /></label>
      <label className="block text-sm font-bold">License key<input type="password" autoComplete="new-password" required={!geo?.configured || account !== geo.account_id} value={key} onChange={e => setKey(e.target.value)} placeholder={geo?.configured ? 'Leave blank to keep the saved key' : ''} className="mt-1 block w-full rounded-lg border border-slate-300 bg-white p-2" /></label>
      <p className="text-sm text-slate-600">Saved on the gateway. The saved key is never sent back to the dashboard. <a href="https://www.maxmind.com/en/accounts/current/license-key" target="_blank" rel="noreferrer" className="text-blue-700 underline">Manage MaxMind license keys</a>.</p>
      <button type="submit" className={button} disabled={working}>{busy ? 'Saving…' : 'Save MaxMind settings'}</button>
    </form>}
  </section>
}
