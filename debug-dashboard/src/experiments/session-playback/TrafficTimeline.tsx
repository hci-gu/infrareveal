import { useEffect, useMemo, useRef } from 'react'
import type { CSSProperties } from 'react'
import { ChevronDown, ChevronRight } from 'lucide-react'
import type { Flow } from '@infrareveal/session-state'
import type { TimelineClip } from '../../model/sessionModel'
import type { CoverageRange } from '../../shared/activity/captureCoverage'
import { usePreference } from '../../shared/ui/preferences'
import { useElementSize } from '../../shared/ui/useElementSize'
import { formatBytes, formatClock } from '../../views/formatters'
import { type TrafficGroup, type TrafficSelection } from './trafficModel'
import { TrafficActivityClip } from './TrafficActivityClip'
import { trafficWaveforms } from './trafficWaveform'
import type { CaptureShortfall } from './trafficCaptureQuality'
import { pixelAtTime, rulerStep, timeAtPixel, type TimeRange } from './trafficTime'
import { importanceLayout, type TrafficImportanceMode, type TrafficVolume } from './trafficImportance'

type Row = { id: string; top: number; height: number; group: TrafficGroup; kind: 'group' | 'flow' | 'dns' | 'evidence'; clip?: TimelineClip }
export function TrafficTimeline({ preferenceKey, groups, flows, shortfalls, range, cursorMs, coverage, collapsed, selected, reveal, importance, contrast, volumes, importanceLoading, importanceError, onImportance, onContrast, onFold, onSelect, onSeek, onPan, onVisibleFlows }: {
  preferenceKey: string; groups: TrafficGroup[]; flows: Map<string, Flow>; shortfalls: Map<string, CaptureShortfall>; range: TimeRange; cursorMs: number; coverage: CoverageRange[]; collapsed: string[]; selected: TrafficSelection | null; reveal: number;
  importance: TrafficImportanceMode; contrast: number; volumes: Map<string, TrafficVolume>; importanceLoading: boolean; importanceError: string | null; onImportance: (value: TrafficImportanceMode) => void; onContrast: (value: number) => void;
  onFold: (id: string) => void; onSelect: (selection: TrafficSelection, time?: number) => void; onSeek: (time: number) => void; onPan: (delta: number) => void; onVisibleFlows: (ids: string[]) => void
}) {
  const { ref: scrollRef, width, height } = useElementSize<HTMLDivElement>()
  const [scrollTop, setScrollTop] = usePreference(`${preferenceKey}scroll`, 0)
  const restored = useRef(false)
  const revealed = useRef(0)
  const anchor = useRef<{ id: string; offset: number } | null>(null)
  const weighted = importance !== 'equal'
  const labelWidth = weighted ? width < 750 ? 250 : 320 : width < 750 ? 224 : 250
  const axisWidth = Math.max(100, width - labelWidth)
  const layout = useMemo(() => importanceLayout(groups, volumes, importance, contrast), [groups, volumes, importance, contrast])
  const waveforms = useMemo(() => trafficWaveforms(groups.flatMap(group => group.clips), range, axisWidth, coverage), [groups, range, axisWidth, coverage])
  const rows = useMemo(() => {
    let top = 0
    const result: Row[] = []
    const add = (group: TrafficGroup, kind: Row['kind'], id: string, clip?: TimelineClip) => { const height = kind === 'group' ? 26 : clip ? layout.height(clip.flowId) : 36; result.push({ group, kind, id, clip, top, height }); top += height }
    for (const group of layout.groups) {
      add(group, 'group', group.id)
      if (collapsed.includes(group.id)) continue
      for (const clip of group.clips) add(group, 'flow', 'flow:' + clip.flowId, clip)
      if (group.dns.length) add(group, 'dns', group.id + ':queries')
      if (group.attributions.length || group.associations.length) add(group, 'evidence', group.id + ':evidence')
    }
    return result
  }, [layout, collapsed])
  useEffect(() => {
    if (!restored.current && rows.length && scrollRef.current) { restored.current = true; scrollRef.current.scrollTop = scrollTop }
  }, [rows.length, scrollRef, scrollTop])
  const totalHeight = rows.length ? rows[rows.length - 1].top + rows[rows.length - 1].height : 0
  const visible = useMemo(() => rows.filter(row => row.top + row.height >= scrollTop - 150 && row.top < scrollTop + height + 150), [rows, scrollTop, height])
  const visibleFlowKey = visible.flatMap(row => row.clip ? [row.clip.flowId] : []).sort().join(',')
  useEffect(() => { onVisibleFlows(visibleFlowKey ? visibleFlowKey.split(',') : []) }, [visibleFlowKey, onVisibleFlows])
  useEffect(() => {
    const saved = anchor.current, scroll = scrollRef.current
    if (!saved || !scroll || scroll.scrollTop < 1) return
    const row = rows.find(item => item.id === saved.id)
    if (row && Math.abs(scroll.scrollTop - row.top - saved.offset) > 1) scroll.scrollTop = row.top + saved.offset
  }, [rows, scrollRef])
  useEffect(() => {
    if (!selected || !reveal || revealed.current === reveal) return
    const row = rows.find(item => selected.kind === 'dns' ? item.kind === 'dns' && item.group.dns.some(q => q.id === selected.id) : selected.kind === 'flow' ? item.clip?.flowId === selected.flowId : item.kind === 'evidence' && (item.group.attributions.some(a => a.id === selected.id) || item.group.associations.some(a => a.id === selected.id)))
    const scroll = scrollRef.current
    if (row) revealed.current = reveal
    if (row && scroll && (row.top < scroll.scrollTop || row.top + row.height > scroll.scrollTop + scroll.clientHeight - 30)) scroll.scrollTo({ top: Math.max(0, row.top - 50) })
  }, [reveal, rows, scrollRef, selected])
  const step = rulerStep(range.toMs - range.fromMs, axisWidth)
  const ticks: number[] = []
  for (let time = Math.ceil(range.fromMs / step) * step; time < range.toMs; time += step) ticks.push(time)
  const x = (time: number) => pixelAtTime(time, axisWidth, range)
  const renderedRows = useMemo(() => {
    const x = (time: number) => pixelAtTime(time, axisWidth, range)
    return visible.map(row => <div key={row.id} className={`traffic-track ${row.kind} ${row.height >= 64 ? 'prominent' : ''} ${row.clip?.flowId === selected?.flowId ? 'selected' : ''}`} style={{ transform: `translateY(${row.top}px)`, height: row.height, '--volume-strength': row.clip ? layout.strengths.get(row.clip.flowId) ?? 0 : 0 } as CSSProperties} data-track-id={row.id} data-bytes={row.clip ? volumes.get(row.clip.flowId)?.bytes ?? 'unknown' : undefined}>
          <div className="traffic-track-label">
            {row.kind === 'group' ? <button type="button" className="track-fold" title={`${row.group.client} / ${row.group.label}`} aria-label={`${collapsed.includes(row.group.id) ? 'Expand' : 'Collapse'} ${row.group.client} ${row.group.label}`} aria-expanded={!collapsed.includes(row.group.id)} onClick={() => onFold(row.group.id)}>{collapsed.includes(row.group.id) ? <ChevronRight size={13} /> : <ChevronDown size={13} />}<span>{row.group.client} / {row.group.label}</span><small>{row.group.clips.length || row.group.dns.length}</small></button> : row.clip ? <><i className="track-color" /><div className="track-identity"><span title={row.clip.label}>{row.clip.label}</span><small>{row.clip.protocol.toUpperCase()}/{row.clip.destinationPort} · {row.clip.destinationIP}</small></div><span className="track-confidence" title={`Hostname confidence: ${row.clip.confidence === 'pending' ? 'Unknown' : row.clip.confidence}`}>{row.clip.confidence === 'pending' ? '?' : row.clip.confidence[0].toUpperCase()}</span>{weighted ? <VolumeLabel volume={volumes.get(row.clip.flowId)} total={layout.totalBytes} recent={importance === 'recent'} /> : <span className="track-counters">{Number.isFinite(flows.get(row.clip.flowId)?.bytes_in) ? formatBytes(flows.get(row.clip.flowId)!.bytes_in) : '—'}<br />{Number.isFinite(flows.get(row.clip.flowId)?.bytes_out) ? formatBytes(flows.get(row.clip.flowId)!.bytes_out) : '—'}</span>}</> : <><i className={`track-color ${row.kind}`} /><div className="track-identity"><span>{row.kind === 'dns' ? 'DNS observations' : 'Attribution / association'}</span><small>{row.kind === 'dns' ? `${row.group.dns.length} questions · answers / aliases` : 'Separate derived evidence'}</small></div></>}
          </div>
          <div className="traffic-lane" style={{ backgroundSize: `${step / (range.toMs - range.fromMs) * axisWidth}px 100%`, backgroundPositionX: `${x(Math.floor(range.fromMs / step) * step)}px` }}>
            {coverage.filter(c => c.level !== 'complete').map(c => <div key={c.fromMs} className={`traffic-coverage ${c.level}`} title={c.detail} style={{ left: x(c.fromMs), width: x(c.toMs) - x(c.fromMs) }} />)}
            {row.kind === 'group' ? <><div className="track-group-line" />{weighted && row.group.clips.length ? <span className="track-group-volume">{volumeLabel(layout.groupVolumes.get(row.group.id))}{importance === 'recent' ? ' captured · last 30s' : ' total'}</span> : null}</> : null}
            {row.clip ? <TrafficActivityClip shortfall={shortfalls.get(row.clip.flowId)} series={waveforms.series.get(row.clip.flowId)} ceiling={waveforms.ceiling} binMs={waveforms.binMs} clip={row.clip} height={row.height - 10} width={axisWidth} range={range} selected={selected?.flowId === row.clip.flowId} onSelect={onSelect} /> : null}
            {row.kind === 'dns' ? row.group.dns.filter(q => Date.parse(q.timestamp) >= range.fromMs && Date.parse(q.timestamp) <= range.toMs).map(q => <button className="traffic-marker dns" type="button" key={q.id} style={{ left: x(Date.parse(q.timestamp)) }} title={`${q.query_name} · ${formatClock(q.timestamp)}`} aria-label={`Inspect DNS ${q.query_name} at ${formatClock(q.timestamp)}`} onClick={() => onSelect({ kind: 'dns', id: q.id }, Date.parse(q.timestamp))} />) : null}
            {row.kind === 'evidence' ? [...row.group.attributions.map(a => ({ kind: 'attribution' as const, id: a.id, flowId: a.flow, time: Date.parse(a.observed_at), label: a.candidate_hostname })), ...row.group.associations.map(a => ({ kind: 'association' as const, id: a.id, flowId: a.flow, time: Date.parse(a.observed_at), label: a.parent_label }))].filter(a => a.time >= range.fromMs && a.time <= range.toMs).map(a => <button className="traffic-marker derived" type="button" key={a.kind + a.id} style={{ left: x(a.time) }} title={`${a.kind} · ${a.label}`} aria-label={`Inspect ${a.kind} ${a.label}`} onClick={() => onSelect({ kind: a.kind, id: a.id, flowId: a.flowId }, a.time)} />) : null}
            <i className="traffic-playhead" style={{ left: 'var(--playhead-left)' }} />
          </div>
        </div>)
  }, [visible, selected, collapsed, onFold, flows, coverage, axisWidth, range, onSelect, step, layout, volumes, weighted, importance, waveforms, shortfalls])
  const incomplete = groups.some(group => group.clips.some(clip => !volumes.get(clip.flowId)?.complete))
  return <section className={`traffic-timeline ${weighted ? 'weighted' : ''}`} aria-label="Traffic timeline">
    <header className="timeline-pane-header"><h2>Session timeline</h2><div className="traffic-legend"><span className="received">Received</span><span className="sent">Sent</span><span className="derived">Derived</span><span className="missing">Incomplete</span></div></header>
    <div className="traffic-importance-controls">
      <label>Track importance<select aria-label="Track importance" value={importance} onChange={event => onImportance(event.target.value as TrafficImportanceMode)}><option value="total">Session data</option><option value="recent">Recent data · 30s</option><option value="equal">Equal tracks</option></select></label>
      <label className="traffic-size-control">Size contrast<input aria-label="Track size contrast" type="range" min="0" max="100" step="5" value={contrast} disabled={!weighted} onChange={event => onContrast(Number(event.target.value))} /><output>{contrast}%</output></label>
      <span className="traffic-importance-note" title={importanceError || undefined}>{importanceLoading ? 'Loading recent data…' : importanceError ? 'Recent data unavailable' : importance === 'recent' ? `Captured payload before playhead${incomplete ? ' · incomplete / unknown' : ''}` : importance === 'total' ? 'Received + sent · full session' : 'Original order · uniform height'}</span>
    </div>
    <div className="traffic-wave-key"><span>Payload rate <b>received above · sent below</b></span><span title="All loaded tracks use the same linear rate scale. The top and bottom of each waveform use this limit, regardless of track height.">Shared scale <b>±{formatBytes(waveforms.ceiling)}/s</b></span><span>{waveforms.binMs / 1000}s average · hover for values</span></div>
    <div className="traffic-tracks" ref={scrollRef} style={{ '--track-label': `${labelWidth}px`, '--playhead-left': `${x(cursorMs)}px` } as CSSProperties} onScroll={event => {
      const top = event.currentTarget.scrollTop; setScrollTop(top)
      const row = rows.find(item => item.top + item.height > top)
      anchor.current = row && top > 0 ? { id: row.id, offset: top - row.top } : null
    }} onWheel={event => { if (event.shiftKey || Math.abs(event.deltaX) > Math.abs(event.deltaY)) onPan((event.deltaX || event.deltaY) / axisWidth * (range.toMs - range.fromMs)) }}>
      <div className="traffic-ruler"><div className="traffic-ruler-label">Track / connection <span>{weighted ? '↓ data volume' : '↓ in · ↑ out'}</span></div><div className="traffic-ruler-axis" aria-label="Timeline ruler; drag to seek" onPointerDown={event => {
        if (event.button !== 0) return
        event.currentTarget.setPointerCapture(event.pointerId)
        onSeek(timeAtPixel(event.clientX - event.currentTarget.getBoundingClientRect().left, axisWidth, range))
      }} onPointerMove={event => { if (event.buttons === 1 && event.currentTarget.hasPointerCapture(event.pointerId)) onSeek(timeAtPixel(event.clientX - event.currentTarget.getBoundingClientRect().left, axisWidth, range)) }}>
        {ticks.map(time => <span className="time-tick" key={time} style={{ left: x(time) }}>{formatClock(time)}</span>)}
        <i className="ruler-head" style={{ left: x(cursorMs) }} />
      </div></div>
      <div className="traffic-row-space" style={{ height: totalHeight }}>
        {renderedRows}
      </div>
      {rows.length === 0 ? <div className="ui-empty"><h3>No matching tracks</h3><p>Change the endpoint or client filter, or wait for observations.</p></div> : null}
    </div>
    <div className="timeline-pan"><button type="button" aria-label="Pan timeline earlier" onClick={() => onPan(-(range.toMs - range.fromMs) / 2)}>← Earlier</button><span>Shift + scroll to move the visible window</span><button type="button" aria-label="Pan timeline later" onClick={() => onPan((range.toMs - range.fromMs) / 2)}>Later →</button></div>
  </section>
}
function VolumeLabel({ volume, total, recent }: { volume?: TrafficVolume; total: number; recent: boolean }) {
  const bytes = volume?.bytes
  const share = bytes != null && total > 0 ? bytes / total * 100 : 0
  const label = volumeLabel(volume)
  return <span className="track-volume" title={`${label} · ${recent ? 'captured payload in the 30 seconds before the playhead' : 'received + sent across the full session'}${volume?.complete ? '' : ' · incomplete or unavailable evidence'}`}>
    <strong>{label}</strong><small>{bytes == null ? 'no capture' : total > 0 ? `${share > 0 && share < .1 ? '<0.1' : share.toFixed(1)}% of shown` : 'no data'}</small>
  </span>
}

function volumeLabel(volume?: TrafficVolume) {
  return volume?.bytes == null ? 'Unknown' : `${formatBytes(volume.bytes)}${volume.complete ? '' : '+'}`
}
