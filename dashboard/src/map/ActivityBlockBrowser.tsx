import { useState } from 'react'
import { useActivityBlocks, useMapWindow, trafficTotals, serviceKey } from '@infrareveal/session-state'
import { formatBytes, formatCursor, formatElapsed } from './format'
import { useLiveList } from './useLiveList'
import { BackToLatest } from './BackToLatest'
import { DEFAULT_TRAFFIC_FILTERS, filterScope } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'

type Props = { sessionId: string; fromMs: number; toMs: number; cursorMs: number; live: boolean; data: WorkspaceProjection; state: WorkspaceState; onSeek: (time: number) => void; onClose: () => void }
export function ActivityBlockBrowser({ sessionId, fromMs, toMs, cursorMs, live, data, state, onSeek, onClose }: Props) {
  // Stable upper boundary avoids restarting pagination on every clock tick.
  const roundedTo = Math.ceil(toMs / 30_000) * 30_000
  const [chosenOrder, setOrder] = useState<'latest' | 'oldest' | null>(null)
  const order = chosenOrder ?? (live ? 'latest' : 'oldest')
  const blocks = useActivityBlocks(sessionId, Math.max(fromMs, roundedTo - 1_800_000), roundedTo, order)
  const [selectedId, setSelected] = useState<string | null>(null)
  const selected = blocks.items.find(block => block.id === selectedId) ?? null
  const trackIds = new Set(data.tracks.map(track => track.id))
  const visible = blocks.items.filter(block => trackIds.has(serviceKey(block)) && block.end_ms > cursorMs - (state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs) && block.start_ms <= cursorMs)
  const { items: orderedItems, scrollRef: listRef, paused: listPaused, back: resumeList, onScroll: scrollList, onFocus: focusList, pause: pauseList } = useLiveList(visible, JSON.stringify([sessionId, order, filterScope(state)]), cursorMs)
  const details = useMapWindow(sessionId, selected?.start_ms ?? 0, selected ? Math.min(selected.end_ms, selected.start_ms + 30 * 60_000) : 0, 50, selected?.id ?? '', Boolean(selected))
  const totals = trafficTotals(details.window.series, details.window.from_ms, details.window.to_ms)
  return <section className="atlas-track-inspector atlas-block-browser" aria-label="Activity blocks">
    <header className="atlas-inspector-heading"><span>ACTIVITY BLOCKS</span><button onClick={onClose} aria-label="Close activity blocks">Close</button></header>
    <label className="atlas-list-order">Sort <select aria-label="Activity block order" value={order} onChange={event => setOrder(event.target.value as 'latest' | 'oldest')}><option value="latest">Latest activity</option><option value="oldest">Oldest first</option></select></label>
    <BackToLatest paused={listPaused} onClick={resumeList} />
    <div ref={listRef} onScroll={scrollList} onFocusCapture={focusList} onClick={pauseList} className="atlas-inspector-scroll">
      <p>Time-bounded service activity. Quiet gaps separate visits; simultaneous services may overlap.</p>
      {orderedItems.map(block => <button className="atlas-block" key={block.id} aria-pressed={selected?.id === block.id} onClick={() => { setSelected(block.id); onSeek(block.start_ms) }}><strong>{block.service_label}</strong><span>{formatCursor(block.start_ms)}–{formatCursor(block.end_ms)} · {block.end_ms - block.start_ms < 1000 ? `${block.end_ms - block.start_ms} ms` : formatElapsed((block.end_ms - block.start_ms) / 1000)}</span><small>{block.client_ip} · {formatBytes(block.sent + block.received)} · {block.provisional ? 'provisional' : 'closed'}{block.clipped ? ' · retained portion' : ''}</small></button>)}
      {blocks.loading && <p>Loading blocks…</p>}
      {blocks.refreshing && <p role="status">Updating · showing last loaded activity</p>}
      {blocks.error && <p role="status">{blocks.error} · Retrying… <button onClick={blocks.refresh}>Retry now</button></p>}
      {blocks.next && <button disabled={blocks.loading || blocks.refreshing} onClick={blocks.more}>Load more blocks</button>}
      {!blocks.loading && !blocks.refreshing && !blocks.error && !visible.length && <p>No activity blocks match the current filters in this interval.</p>}
      {selected && <section className="atlas-block-detail"><h3>{selected.service_label}</h3><p>{selected.confidence} confidence · {selected.quality} capture · {selected.active_ms < 1000 ? `${selected.active_ms} ms` : formatElapsed(selected.active_ms / 1000)} active</p><p>Originally started {formatCursor(selected.original_start_ms)} UTC. Retained block totals: {formatBytes(selected.received)} received / {formatBytes(selected.sent)} sent.</p>{details.loading ? <p>Loading block evidence…</p> : details.hasData ? <><p>Loaded interval: {formatBytes(totals.received)} received / {formatBytes(totals.sent)} sent.</p>{[...new Set(details.window.series.map(chunk => `${chunk.destination_ip}:${chunk.destination_port} ${chunk.protocol} · ${chunk.evidence.source || 'independent'} ${chunk.evidence.confidence}`))].map(item => <p key={item}>{item}</p>)}</> : null}{details.error && <p role="status">{details.error}</p>}</section>}
    </div>
  </section>
}
