import { useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import { captureQuality, getDiagnostics, setTimelinePlayback, trafficTotals, useActivityBlocks, useMapWindow, useSession } from '@infrareveal/session-state'
import type { ActivityBlock, DiagnosticKind } from '@infrareveal/session-state'
import { useLabPlayback } from '../proxy-lab/state/useLabPlayback'
import { LabReplayControls } from '../proxy-lab/components/LabReplayControls'
import { formatClock } from '../../views/formatters'
import './activity.css'

export function SessionPlaybackPage() {
  const { sessionID = '' } = useParams()
  const { timeline, refresh } = useSession(sessionID)
  const { manifest, cursorMs, liveEdgeMs, playback, rate } = timeline
  const [query, setQuery] = useState(''), [selectedId, setSelectedId] = useState<string | null>(null)
  const [span, setSpan] = useState(5 * 60_000)
  const retained = manifest?.retained_from_ms ?? 0
  const anchor = Math.floor(cursorMs / 30_000) * 30_000
  const from = Math.max(retained, anchor - span + 30_000), to = anchor + 30_000
  const window = useMapWindow(sessionID, from, to, manifest?.policy.bucket_ms ?? 50)
  const blocks = useActivityBlocks(sessionID, from, to)
  const selected = blocks.items.find(block => block.id === selectedId) ?? null
  const detailFrom = selected ? Math.max(selected.start_ms, Math.min(cursorMs - 30_000, selected.end_ms - 60_000)) : 0
  const detail = useMapWindow(sessionID, detailFrom, selected ? Math.min(selected.end_ms, detailFrom + 60_000) : 0, manifest?.policy.bucket_ms ?? 50, selected?.id ?? '', Boolean(selected))
  const totals = useMemo(() => trafficTotals(window.window.series, from, cursorMs), [window.window.series, from, cursorMs])
  const quality = captureQuality(window.window.coverage, from, cursorMs)
  useLabPlayback({ sessionId: sessionID, epochMs: retained, endMs: liveEdgeMs, active: Boolean(manifest?.active), demo: false })
  const seek = (time: number) => setTimelinePlayback({ cursorMs: Math.max(retained, Math.min(liveEdgeMs, time)), playback: 'paused' })
  const visible = blocks.items.filter(block => `${block.service_label} ${block.client_ip}`.toLowerCase().includes(query.toLowerCase()))
  if (!manifest) return <main className="activity-page"><Link to="/">Sessions</Link><h1>{timeline.error || 'Loading session…'}</h1><button onClick={() => void refresh()}>Retry</button></main>
  return <main className="activity-page"><header><div><Link to="/">← Sessions</Link><h1>{manifest.name}</h1><p>{manifest.active ? 'Live' : 'Recorded'} · Capture {quality} · {formatClock(cursorMs)}</p></div><Link to={`/proxy-lab/${sessionID}`}>Gateway lab →</Link></header>
    {(timeline.error || window.error) && <p role="status">{timeline.error || window.error}<button onClick={() => { void refresh(); window.refresh() }}>Retry</button></p>}
    <section className="activity-totals"><div><strong>{bytes(totals.received)}</strong><span>Received</span></div><div><strong>{bytes(totals.sent)}</strong><span>Sent</span></div><div><strong>{quality}</strong><span>Capture in selected window</span></div><label>Window <select value={span} onChange={event => setSpan(Number(event.target.value))}><option value={60_000}>1 minute</option><option value={300_000}>5 minutes</option><option value={1800_000}>30 minutes</option></select></label><p>Captured wire bytes from {formatClock(from)} to the playhead. ACK-only and independent traffic remain included.</p></section>
    <LabReplayControls epochMs={retained} endMs={liveEdgeMs} cursorMs={cursorMs} playback={playback} rate={rate} active={manifest.active} events={[]} onSeek={seek} />
    <div className="activity-layout"><section><h2>Activity blocks</h2><p>Service activity separated by quiet gaps. These intervals do not prove browsing attention.</p><input type="search" aria-label="Search activity blocks" placeholder="Search service or client…" value={query} onChange={event => setQuery(event.target.value)} />
      <div className="activity-blocks">{visible.map(block => <button key={block.id} className="activity-block" aria-pressed={block.id === selectedId} onClick={() => { setSelectedId(block.id); seek(block.start_ms) }}><strong>{block.service_label}</strong><span>{formatClock(block.start_ms)} – {formatClock(block.end_ms)} · {(block.end_ms-block.start_ms)/1000}s</span><small>{block.client_ip} · {bytes(block.sent+block.received)} · {block.quality}{block.provisional ? ' · provisional' : ''}{block.clipped ? ' · clipped by retention' : ''}</small><span className="activity-block-bar"><i style={{ left: `${Math.max(0,(block.start_ms-retained)/Math.max(1,liveEdgeMs-retained))*100}%`, width: `${Math.max(.3,(block.end_ms-block.start_ms)/Math.max(1,liveEdgeMs-retained)*100)}%` }} /></span></button>)}</div>
      {blocks.loading && <p>Loading blocks…</p>}{blocks.error && <p role="status">{blocks.error}<button onClick={blocks.refresh}>Retry</button></p>}{blocks.next && <button onClick={blocks.more} disabled={blocks.loading}>Load more</button>}{!blocks.loading && !visible.length && <p>No matching activity blocks.</p>}
    </section><aside>{selected ? <BlockDetails block={selected} /> : <p>Select an activity block to inspect its evidence.</p>}{selected && <><h3>Destinations in loaded minute</h3><p>{formatClock(detailFrom)}–{formatClock(detail.window.to_ms)}. Seek within the block to inspect another minute.</p>{detail.loading ? <p>Loading evidence…</p> : [...new Map(detail.window.series.map(chunk => [`${chunk.destination_ip}:${chunk.destination_port}:${chunk.protocol}`, chunk])).values()].map(chunk => <details key={chunk.id}><summary>{chunk.destination_ip}:{chunk.destination_port} · {chunk.protocol}</summary><p>{chunk.evidence.hostname || 'Independent endpoint'} · {chunk.evidence.source || 'No hostname signal'} · {chunk.evidence.confidence}{chunk.evidence.ambiguous ? ' · ambiguous' : ''}</p><p>{chunk.sealed ? 'Classification sealed' : 'Classification provisional'} · policy {chunk.evidence.policy_version}</p></details>)}{detail.error && <p role="status">{detail.error}</p>}</>}
      <DiagnosticsPanel sessionID={sessionID} from={from} to={to} enabled={manifest.diagnostics} />
    </aside></div>
  </main>
}
function BlockDetails({ block }: { block: ActivityBlock }) { return <section><h2>{block.service_label}</h2><dl><dt>Client</dt><dd>{block.client_ip}</dd><dt>Original start</dt><dd>{formatClock(block.original_start_ms)}</dd><dt>Retained interval</dt><dd>{formatClock(block.start_ms)}–{formatClock(block.end_ms)}</dd><dt>Active time</dt><dd>{(block.active_ms/1000).toFixed(2)} s</dd><dt>Retained captured bytes</dt><dd>{bytes(block.received)} received / {bytes(block.sent)} sent</dd><dt>Evidence</dt><dd>{block.confidence} confidence · {block.quality} capture</dd></dl><p>{block.provisional ? 'Provisional: recent evidence can still revise this block.' : 'Closed block.'}{block.clipped ? ' Its original start is preserved; old traffic has expired.' : ''}</p></section> }
function DiagnosticsPanel({ sessionID, from, to, enabled }: { sessionID: string; from: number; to: number; enabled: Record<DiagnosticKind, boolean> }) {
  const [kind, setKind] = useState<DiagnosticKind>('flows'), [token, setToken] = useState('')
  const scope = `${sessionID}:${kind}:${from}:${to}`
  const [result, setResult] = useState({ scope: '', records: [] as Record<string, unknown>[], error: '' }), [pending, setPending] = useState('')
  const records = result.scope === scope ? result.records : [], error = result.scope === scope ? result.error : '', loading = pending === scope
  const request = useRef<AbortController | null>(null)
  useEffect(() => () => request.current?.abort(), [sessionID, kind, from, to])
  const load = async () => { request.current?.abort(); const controller = new AbortController(); request.current = controller; setPending(scope); try { const response = await getDiagnostics(sessionID, kind, from, to, token, controller.signal); if (!controller.signal.aborted) setResult({ scope, records: response.items, error: '' }) } catch (error) { if (!controller.signal.aborted) setResult({ scope, records: [], error: error instanceof Error ? error.message : 'Diagnostics unavailable' }) } finally { if (!controller.signal.aborted) setPending('') } }
  return <details className="activity-diagnostics"><summary>Optional diagnostics</summary><p>Only diagnostics recorded for this session are available. Administrative authentication is required.</p><select aria-label="Diagnostic records" value={kind} onChange={event => setKind(event.target.value as DiagnosticKind)}>{(['flows','dns','gate'] as const).map(value => <option key={value} value={value}>{value}{enabled[value] ? '' : ' · not recorded'}</option>)}</select>{enabled[kind] ? <><input type="password" aria-label="Administrator token" value={token} onChange={event => setToken(event.target.value)} placeholder="Administrator token" autoComplete="off" /><button disabled={loading || !token} onClick={() => void load()}>Load diagnostics for window</button></> : <p>Not recorded for this session.</p>}{error && <p role="status">{error}</p>}<pre>{records.length ? JSON.stringify(records, null, 2) : ''}</pre></details>
}
function bytes(value: number) { return value < 1024 ? `${value} B` : value < 1024**2 ? `${(value/1024).toFixed(1)} KB` : `${(value/1024**2).toFixed(1)} MB` }
