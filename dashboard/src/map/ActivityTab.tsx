import { useState } from 'react'
import type { CSSProperties } from 'react'
import { useActivityBlocks, useMapWindow, trafficTotals, serviceKey } from '@infrareveal/session-state'
import type { ActivityBlock, TrafficChunk } from '@infrareveal/session-state'
import { formatBytes, formatCursor, formatElapsed } from './format'
import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import { DEFAULT_TRAFFIC_FILTERS, filterScope } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import { colorCSS } from './mapTracks'
import type { TrackColors } from './mapTracks'
import type { FeedLine } from './liveFeed'
import type { LiveFeedState } from './useLiveFeed'

export type ActivityTabProps = {
  sessionId: string; chunks: readonly TrafficChunk[]; cursorMs: number; live: boolean
  /** Live session with the playhead at the live edge; paused or scrubbed history is not. */
  following: boolean
  fromMs: number; toMs: number; data: WorkspaceProjection; state: WorkspaceState; onSeek: (time: number) => void
}


/** A raw view of capture as it reaches the dashboard, then the visits it forms.
 * The feed is owned by the always-mounted pane, so switching tabs keeps history. */
export function ActivityTab({ feed, ...props }: ActivityTabProps & { feed: LiveFeedState }) {
  return <div className="atlas-activity">
    <LiveFeed {...props} feed={feed} />
    <VisitList {...props} clientColors={feed.clientColors} />
  </div>
}

/** The last address part is enough to tell a few devices apart; the chip color does the rest. */
const shortClient = (ip: string) => /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? `.${ip.split('.')[3]}` : ip

function LiveFeed({ following: live, feed }: ActivityTabProps & { feed: LiveFeedState }) {
  const { lines, rate, clientColors } = feed
  const [frozen, setFrozen] = useState<FeedLine[] | null>(null)
  const shown = frozen ?? lines
  const newest = frozen?.[0]?.atMs ?? Infinity
  const waiting = frozen ? lines.filter(line => line.atMs > newest).length : 0
  const peak = Math.max(1, ...rate)
  // Capture reaches the browser ~2 s late, so the newest second is usually still empty.
  const perSecond = rate.length ? Math.round(rate.reduce((sum, count) => sum + count, 0) / rate.length * 10) / 10 : 0
  return <section className="atlas-feed" aria-labelledby="feed-title">
    <header className="atlas-feed-heading">
      <div><h3 id="feed-title"><span className="atlas-feed-live" data-live={live || undefined} aria-hidden="true" />{live ? 'Live capture' : 'Capture at playhead'}</h3>
        <p>Captured byte samples in 250 ms ticks, not individual packets.</p></div>
      <div className="atlas-feed-rate" title="Feed lines per second, averaged over the last 15 seconds">
        <svg viewBox={`0 0 ${rate.length * 4} 18`} aria-hidden="true">{rate.map((count, i) => <rect key={i} x={i * 4} y={18 - Math.max(1, count / peak * 18)} width={3} height={Math.max(1, count / peak * 18)} rx={1} />)}</svg>
        <span><strong>{perSecond}</strong> lines/s</span>
      </div>
    </header>
    <div className="atlas-feed-scroll" onPointerEnter={() => setFrozen(lines)} onPointerLeave={() => setFrozen(null)}>
      {frozen && <button type="button" className="atlas-feed-paused" onClick={() => setFrozen(lines)}>Paused while hovering{waiting > 0 ? ` · ${waiting} new` : ''}</button>}
      {!shown.length ? <p className="atlas-feed-empty">{live ? 'Waiting for traffic…' : 'No captured traffic just before the playhead.'}</p>
        : <ol aria-label="Captured traffic, newest first">{shown.map((line, index) => <li key={line.id} className="atlas-feed-line" style={{ '--age': Math.min(1, index / 60), '--client': colorCSS(clientColors.get(line.clientIp)) } as CSSProperties}>
          <span className="atlas-feed-time">{formatCursor(line.atMs)}<small>.{String(line.atMs % 1000).padStart(3, '0')}</small></span>
          <span className="atlas-feed-client" title={line.clientIp}><i aria-hidden="true" />{shortClient(line.clientIp)}</span>
          <span className="atlas-feed-bytes">{line.received > 0 && <span className="atlas-down">↓ {formatBytes(line.received)}</span>}{line.sent > 0 && <span className="atlas-up">↑ {formatBytes(line.sent)}</span>}</span>
          <span className="atlas-feed-service" title={line.host || undefined}>{line.service}</span>
          <span className="atlas-feed-endpoint">{line.endpoint} {line.protocol}</span>
        </li>)}</ol>}
    </div>
  </section>
}

function VisitList({ sessionId, fromMs, toMs, cursorMs, live, data, state, onSeek, clientColors }: ActivityTabProps & { clientColors: TrackColors }) {
  // Stable upper boundary avoids restarting pagination on every clock tick.
  const roundedTo = Math.ceil(toMs / 30_000) * 30_000
  const [chosenOrder, setOrder] = useState<'latest' | 'oldest' | null>(null)
  const order = chosenOrder ?? (live ? 'latest' : 'oldest')
  const blocks = useActivityBlocks(sessionId, Math.max(fromMs, roundedTo - 1_800_000), roundedTo, order)
  const [selectedId, setSelected] = useState<string | null>(null)
  const trackIds = new Set(data.tracks.map(track => track.id))
  const visible = blocks.items.filter(block => trackIds.has(serviceKey(block)) && block.end_ms > cursorMs - (state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs) && block.start_ms <= cursorMs)
  const { items, scrollRef, paused, back, onScroll, onFocus, pause } = useLiveList(visible, JSON.stringify([sessionId, order, filterScope(state)]), cursorMs)
  const longest = Math.max(1_000, ...items.map(block => block.end_ms - block.start_ms))
  return <section className="atlas-visits" aria-labelledby="visits-title">
    <header className="atlas-visits-heading">
      <div><h3 id="visits-title">Visits <small>{visible.length}</small></h3><p>Service activity separated by quiet gaps.</p></div>
      <label className="atlas-insight-select"><span className="atlas-sr-only">Visit order</span>
        <select value={order} onChange={event => setOrder(event.target.value as 'latest' | 'oldest')}><option value="latest">Latest</option><option value="oldest">Oldest</option></select></label>
    </header>
    <BackToLatest paused={paused} onClick={back} />
    <div ref={scrollRef} onScroll={onScroll} onFocusCapture={onFocus} onClick={pause} className="atlas-visits-scroll">
      {items.map(block => <Visit key={block.id} block={block} longest={longest} color={colorCSS(clientColors.get(block.client_ip || block.client_id))} open={selectedId === block.id}
        onToggle={() => { setSelected(selectedId === block.id ? null : block.id); if (selectedId !== block.id) onSeek(block.start_ms) }} />)}
      {blocks.loading && <p className="atlas-visits-note">Loading visits…</p>}
      {blocks.refreshing && <p className="atlas-visits-note" role="status">Updating. Showing last loaded activity.</p>}
      {blocks.error && <p className="atlas-visits-note" role="status">{blocks.error}. Retrying… <button type="button" onClick={blocks.refresh}>Retry now</button></p>}
      {blocks.next && <button type="button" className="atlas-visits-more" disabled={blocks.loading || blocks.refreshing} onClick={blocks.more}>Load more visits</button>}
      {!blocks.loading && !blocks.refreshing && !blocks.error && !visible.length && <p className="atlas-visits-note">No visits match the current filters in this window.</p>}
    </div>
  </section>
}

const duration = (ms: number) => ms < 1000 ? `${ms} ms` : formatElapsed(ms / 1000)

function Visit({ block, longest, color, open, onToggle }: { block: ActivityBlock; longest: number; color: string; open: boolean; onToggle: () => void }) {
  const span = block.end_ms - block.start_ms
  return <div className="atlas-visit" data-open={open || undefined}>
    <button type="button" aria-expanded={open} onClick={onToggle} style={{ '--client': color } as CSSProperties}>
      <span className="atlas-visit-service">{block.service_label}{block.provisional && <small>ongoing</small>}</span>
      <span className="atlas-visit-bytes">{formatBytes(block.sent + block.received)}</span>
      <span className="atlas-visit-meta"><i aria-hidden="true" />{block.client_ip} · {formatCursor(block.start_ms)} · {duration(span)}</span>
      <span className="atlas-visit-bar" aria-hidden="true"><i style={{ width: `${Math.max(2, span / longest * 100)}%` }} /></span>
    </button>
    {open && <VisitDetail block={block} />}
  </div>
}

function VisitDetail({ block }: { block: ActivityBlock }) {
  const details = useMapWindow(block.session, block.start_ms, Math.min(block.end_ms, block.start_ms + 30 * 60_000), 50, block.id, true)
  const totals = trafficTotals(details.window.series, details.window.from_ms, details.window.to_ms)
  const endpoints = [...new Set(details.window.series.map(chunk => `${chunk.destination_ip}:${chunk.destination_port} ${chunk.protocol} · ${chunk.evidence.source || 'independent'} ${chunk.evidence.confidence}`))]
  return <div className="atlas-visit-detail">
    <dl>
      <div><dt>Naming</dt><dd>{block.confidence} confidence</dd></div>
      <div><dt>Capture</dt><dd>{block.quality}</dd></div>
      <div><dt>Active</dt><dd>{duration(block.active_ms)}</dd></div>
      <div><dt>Started</dt><dd>{formatCursor(block.original_start_ms)} UTC</dd></div>
      <div><dt>Totals</dt><dd><span className="atlas-down">↓ {formatBytes(block.received)}</span> <span className="atlas-up">↑ {formatBytes(block.sent)}</span>{block.clipped ? ' · retained part' : ''}</dd></div>
    </dl>
    {details.loading ? <p>Loading endpoints…</p> : details.hasData && <>
      <p className="atlas-visit-loaded">Loaded interval: ↓ {formatBytes(totals.received)} · ↑ {formatBytes(totals.sent)}</p>
      <ul>{endpoints.map(item => <li key={item}>{item}</li>)}</ul>
    </>}
    {details.error && <p role="status">{details.error}</p>}
  </div>
}
