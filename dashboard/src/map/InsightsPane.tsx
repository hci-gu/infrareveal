import { memo, useCallback, useEffect, useMemo, useState } from 'react'
import type { CSSProperties } from 'react'
import { MapIcon } from './MapIcon'
import { formatBytes } from './format'
import { DEFAULT_TRAFFIC_FILTERS } from './mapWorkspace'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import { countryShares, trackShares } from './trackShares'
import type { Share } from './trackShares'
import { TrackColors } from './mapTracks'
import { DirectionScatter } from './ListenTalkChart'
import { ActivityTab } from './ActivityTab'
import { useLiveFeed } from './useLiveFeed'
import type { ActivityTabProps } from './ActivityTab'
import { domainWeights, fontSize, layoutWords, measureText } from './wordCloud'
import { hopLabel, summarizeCrossings } from './seaCrossings'
import { LATENCY_BANDS, summarizeLatency } from './latency'
import type { CrossingClass } from './seaCrossings'

const WINDOW_LABELS: Record<number, string> = { 30_000: '30 seconds', 60_000: 'minute', 300_000: '5 minutes', 1_800_000: '30 minutes' }
const SIZE = 200
const OUTER = 96
const INNER = 62

type ShareMode = 'track' | 'country'
const MODES: Record<ShareMode, { title: string; unit: [string, string] }> = {
  track: { title: 'Traffic by track', unit: ['track', 'tracks'] },
  country: { title: 'Traffic by country', unit: ['country', 'countries'] },
}

export type SidePaneTab = 'insights' | 'activity'

/** One docked pane for views that look at the session rather than filter it.
 * Insights summarizes the filtered workspace; Activity shows capture arriving. */
export const SidePane = memo(function SidePane({ tab, data, state, loading, activity, onClose }: {
  tab: SidePaneTab | null; data: WorkspaceProjection; state: WorkspaceState; loading: boolean
  activity: Omit<ActivityTabProps, 'data' | 'state'>; onClose: () => void
}) {
  const open = tab !== null
  const close = useCallback(() => { const from = tab; onClose(); document.getElementById(`${from ?? 'insights'}-toggle`)?.focus({ preventScroll: true }) }, [onClose, tab])
  useEffect(() => {
    if (!open) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || document.querySelector('.atlas-filter-drawer[data-open]')) return
      event.preventDefault(); close()
    }
    document.addEventListener('keydown', onKey)
    return () => document.removeEventListener('keydown', onKey)
  }, [open, close])
  const windowMs = state.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs
  const [mode, setMode] = useState<ShareMode>('track')
  // Device chips keep one color per client; the feed keeps its lines across tab switches.
  const [clientColors] = useState(() => new TrackColors())
  const feed = { ...useLiveFeed(activity.chunks, activity.cursorMs, activity.sessionId, state), clientColors }
  return <aside id="side-pane" className="atlas-insights" aria-label={tab === 'activity' ? 'Activity' : 'Insights'} aria-hidden={!open} inert={!open} data-open={open || undefined} data-tab={tab ?? undefined}>
    {/* The header toggles name and switch the tab; the pane keeps only a close control. */}
    <button type="button" className="atlas-icon-button atlas-side-close" aria-label={`Close ${tab ?? 'panel'}`} onClick={close}><MapIcon name="close" size={16} /></button>
    <div className="atlas-side-body">
      {tab === 'insights' && <>
        <ShareChart mode={mode} onMode={setMode} data={data} loading={loading} windowLabel={WINDOW_LABELS[windowMs] ?? `${Math.round(windowMs / 1000)} s`} />
        <RoundTrips data={data} loading={loading} />
        <SeaCrossings data={data} loading={loading} />
        <DirectionScatter data={data} loading={loading} />
        <DomainCloud data={data} loading={loading} />
      </>}
      {tab === 'activity' && <ActivityTab {...activity} data={data} state={state} feed={feed} />}
    </div>
  </aside>
})

function ShareChart({ mode, onMode, data, loading, windowLabel }: { mode: ShareMode; onMode: (mode: ShareMode) => void; data: WorkspaceProjection; loading: boolean; windowLabel: string }) {
  // Country hues are assigned once per pane, so they stay put as live ranks change.
  const [countryColors] = useState(() => new TrackColors())
  const { total, shares } = useMemo(() => mode === 'track' ? trackShares(data.tracks) : countryShares(data.bySeries.values(), countryColors), [mode, data.tracks, data.bySeries, countryColors])
  const parts = mode === 'track' ? data.tracks.length : new Set([...data.bySeries.values()].filter(series => series.bytes > 0).map(series => series.country || '')).size
  const [active, setActive] = useState<string | null>(null)
  const arcs = useMemo(() => donutArcs(shares), [shares])
  const focused = shares.find(share => share.id === active) ?? null
  const { title, unit } = MODES[mode]
  return <section className="atlas-insight" aria-labelledby="share-chart-title">
    <div className="atlas-insight-heading">
      <h3 id="share-chart-title">{title}</h3>
      <label className="atlas-insight-select"><span className="atlas-sr-only">Group traffic by</span>
        <select value={mode} onChange={event => { setActive(null); onMode(event.target.value as ShareMode) }}>
          <option value="track">Track</option>
          <option value="country">Country</option>
        </select>
      </label>
    </div>
    <p className="atlas-insight-help">Share of downloaded and sent bytes · current filters, last {windowLabel}.</p>
    {!shares.length ? <p className="atlas-insight-empty">{loading ? 'Loading traffic…' : 'No traffic in this window.'}</p> : <>
      <div className="atlas-donut">
        <svg viewBox={`0 0 ${SIZE} ${SIZE}`} role="img" aria-label={`${title}: ${shares.map(share => `${share.label} ${percent(share.share)}`).join(', ')}`} onPointerLeave={() => setActive(null)}>
          {arcs.map(({ share, path }) => <path key={share.id} d={path} className="atlas-donut-slice" data-other={share.color ? undefined : true} data-dimmed={active && active !== share.id ? true : undefined}
            style={share.color ? { fill: share.color } as CSSProperties : undefined} onPointerEnter={() => setActive(share.id)} />)}
        </svg>
        <div className="atlas-donut-center" aria-hidden="true">
          {focused ? <><strong>{percent(focused.share)}</strong><span>{focused.label}</span><small>{formatBytes(focused.bytes)}</small></>
            : <><strong>{formatBytes(total)}</strong><span>{parts} {parts === 1 ? unit[0] : unit[1]}</span></>}
        </div>
      </div>
      <table className="atlas-share-table">
        <caption className="atlas-sr-only">{title}</caption>
        <thead className="atlas-sr-only"><tr><th scope="col">{mode === 'track' ? 'Track' : 'Country'}</th><th scope="col">Bytes</th><th scope="col">Share</th></tr></thead>
        <tbody>{shares.map(share => <tr key={share.id} data-active={active === share.id || undefined} onPointerEnter={() => setActive(share.id)} onPointerLeave={() => setActive(null)}>
          <th scope="row"><i className="atlas-share-swatch" data-other={share.color ? undefined : true} style={share.color ? { background: share.color } : undefined} /><span><span>{share.label}</span><small>{share.detail}</small></span></th>
          <td>{formatBytes(share.bytes)}</td>
          <td>{percent(share.share)}</td>
        </tr>)}</tbody>
      </table>
    </>}
  </section>
}

const LATENCY_LEGEND = [...LATENCY_BANDS.map(band => ({ id: band.id, label: band.label })), { id: 'unmeasured', label: 'Not measured' }]

/** How far away the traffic really was, from round trips measured passively at the gateway. */
function RoundTrips({ data, loading }: { data: WorkspaceProjection; loading: boolean }) {
  const summary = useMemo(() => summarizeLatency(data.locations, data.scene.origin), [data.locations, data.scene.origin])
  const bands = LATENCY_LEGEND.filter(band => summary.bands[band.id] > 0)
  return <section className="atlas-insight" aria-labelledby="round-trips-title">
    <h3 id="round-trips-title">Round trips</h3>
    <p className="atlas-insight-help">Traffic by the lowest round trip measured at the gateway (connection handshakes). Show it on the map with Latency.</p>
    {!summary.total ? <p className="atlas-insight-empty">{loading ? 'Loading traffic…' : 'No traffic in this window.'}</p> : <>
      <div className="atlas-crossing-bar" role="img" aria-label={bands.map(band => `${band.label} ${percent(summary.bands[band.id] / summary.total)}`).join(', ')}>
        {bands.map(band => <i key={band.id} data-latency={band.id} style={{ width: `${summary.bands[band.id] / summary.total * 100}%` }} />)}
      </div>
      <ul className="atlas-crossing-legend">
        {bands.map(band => <li key={band.id}><i data-latency={band.id} /><span>{band.label}</span><strong>{percent(summary.bands[band.id] / summary.total)}</strong></li>)}
      </ul>
      {summary.contradicted > 0 && <p className="atlas-insight-help" data-latency-contradicted={summary.contradicted}>
        {percent(summary.contradicted / summary.locatedMeasured)} of measured traffic answered faster than light allows from its IP location: it was served from nearby, not where the address is registered.
      </p>}
    </>}
  </section>
}

const CROSSING_CLASSES: { id: CrossingClass; label: string }[] = [
  { id: 'required', label: 'Crossed the sea' },
  { id: 'possible', label: 'Likely crossed the sea' },
  { id: 'nearby', label: 'Served nearby (measured)' },
  { id: 'none', label: 'Overland or nearby' },
  { id: 'edge', label: 'Global edge network' },
  { id: 'unknown', label: 'Unknown location' },
]

/** How much traffic had to go under the sea, inferred from IP geography alone. */
function SeaCrossings({ data, loading }: { data: WorkspaceProjection; loading: boolean }) {
  const summary = useMemo(() => summarizeCrossings(data.locations, data.scene.origin), [data.locations, data.scene.origin])
  const classes = CROSSING_CLASSES.filter(item => summary.totals[item.id] > 0)
  return <section className="atlas-insight" aria-labelledby="sea-crossings-title">
    <h3 id="sea-crossings-title">Sea crossings</h3>
    <p className="atlas-insight-help">Inferred from where destinations are located; cables are not observed. Show them on the map with Cables.</p>
    {!summary.total ? <p className="atlas-insight-empty">{loading ? 'Loading traffic…' : 'No traffic in this window.'}</p> : <>
      <div className="atlas-crossing-bar" role="img" aria-label={classes.map(item => `${item.label} ${percent(summary.totals[item.id] / summary.total)}`).join(', ')}>
        {classes.map(item => <i key={item.id} data-crossing={item.id} style={{ width: `${summary.totals[item.id] / summary.total * 100}%` }} />)}
      </div>
      <ul className="atlas-crossing-legend">
        {classes.map(item => <li key={item.id}><i data-crossing={item.id} /><span>{item.label}{item.id === 'edge' && summary.edgeNetworks.length ? <small>{summary.edgeNetworks.join(', ')}</small> : null}</span><strong>{percent(summary.totals[item.id] / summary.total)}</strong></li>)}
      </ul>
      {summary.hops.length > 0 && <table className="atlas-share-table">
        <caption className="atlas-sr-only">Sea crossings by bytes</caption>
        <thead className="atlas-sr-only"><tr><th scope="col">Crossing</th><th scope="col">Bytes</th></tr></thead>
        <tbody>{summary.hops.slice(0, 5).map(entry => <tr key={entry.hop.id}>
          <th scope="row"><span><span>{hopLabel(entry.hop)}</span><small>{entry.confidence === 'required' ? 'Required' : 'Likely'} · {entry.hop.candidates.length} candidate {entry.hop.candidates.length === 1 ? 'cable' : 'cables'}</small></span></th>
          <td>{formatBytes(entry.bytes)}</td>
        </tr>)}</tbody>
      </table>}
    </>}
  </section>
}

const CLOUD_WIDTH = 300
const CLOUD_HEIGHT = 220

function DomainCloud({ data, loading }: { data: WorkspaceProjection; loading: boolean }) {
  const { words, total, excluded } = useMemo(() => domainWeights(data.bySeries.values()), [data.bySeries])
  const [fontsReady, setFontsReady] = useState(0)
  useEffect(() => {
    let stopped = false
    document.fonts?.ready.then(() => { if (!stopped) setFontsReady(value => value + 1) })
    return () => { stopped = true }
  }, [])
  // Positions depend only on which domains appear and their size steps, so the
  // cloud stays still between live updates that do not change either.
  const layoutKey = words.map(word => `${word.domain}:${fontSize(word.bytes, words[0].bytes)}`).join('|')
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const placed = useMemo(() => layoutWords(words, CLOUD_WIDTH, CLOUD_HEIGHT, measureText), [layoutKey, fontsReady])
  const current = new Map(words.map(word => [word.domain, word]))
  const [active, setActive] = useState<string | null>(null)
  const focused = active ? current.get(active) : undefined
  const hiddenWords = words.length - placed.length
  return <section className="atlas-insight" aria-labelledby="domain-cloud-title">
    <h3 id="domain-cloud-title">Domains</h3>
    <p className="atlas-insight-help">Word size follows bytes exchanged.</p>
    {!placed.length ? <p className="atlas-insight-empty">{loading ? 'Loading domains…' : 'No named domains in this window.'}</p> : <>
      <svg className="atlas-word-cloud" viewBox={`0 0 ${CLOUD_WIDTH} ${CLOUD_HEIGHT}`} aria-hidden="true" onPointerLeave={() => setActive(null)}>
        {placed.map(word => <text key={word.domain} x={word.x} y={word.y} fontSize={word.size} data-tier={word.tier} data-dimmed={active && active !== word.domain ? true : undefined}
          onPointerEnter={() => setActive(word.domain)}>{word.domain}</text>)}
      </svg>
      <p className="atlas-word-cloud-caption" aria-live="polite">{focused ? <><strong>{focused.domain}</strong> · {formatBytes(focused.bytes)} · {percent(focused.share)}</>
        : <>{hiddenWords > 0 ? `Top ${placed.length} of ${words.length} domains` : `${words.length} ${words.length === 1 ? 'domain' : 'domains'}`} · {formatBytes(total)}{excluded > 0 ? ` · ${formatBytes(excluded)} unnamed` : ''}</>}</p>
      <ol className="atlas-sr-only" aria-label="Domains by bytes">{words.map(word => <li key={word.domain}>{word.domain}: {formatBytes(word.bytes)}, {percent(word.share)}</li>)}</ol>
    </>}
  </section>
}

const percent = (share: number) => share >= 0.995 ? '100%' : share < 0.01 ? '<1%' : `${Math.round(share * 100)}%`

/** Annular sectors from 12 o'clock, clockwise. A sole slice is a full ring. */
function donutArcs(shares: Share[]) {
  const c = SIZE / 2
  let angle = -Math.PI / 2
  return shares.map(share => {
    const sweep = share.share * Math.PI * 2
    const start = angle
    angle += sweep
    if (sweep >= Math.PI * 2 - 1e-6) {
      return { share, path: `M${c - OUTER} ${c}a${OUTER} ${OUTER} 0 1 0 ${OUTER * 2} 0a${OUTER} ${OUTER} 0 1 0 ${-OUTER * 2} 0ZM${c - INNER} ${c}a${INNER} ${INNER} 0 1 1 ${INNER * 2} 0a${INNER} ${INNER} 0 1 1 ${-INNER * 2} 0Z` }
    }
    const large = sweep > Math.PI ? 1 : 0
    const point = (r: number, a: number) => `${(c + r * Math.cos(a)).toFixed(2)} ${(c + r * Math.sin(a)).toFixed(2)}`
    return { share, path: `M${point(OUTER, start)}A${OUTER} ${OUTER} 0 ${large} 1 ${point(OUTER, angle)}L${point(INNER, angle)}A${INNER} ${INNER} 0 ${large} 0 ${point(INNER, start)}Z` }
  })
}
