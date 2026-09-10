import { useMemo, useState } from 'react'
import { useElementSize } from '../../shared/ui/useElementSize'
import { CopyButton } from '../../shared/ui/CopyButton'
import { formatClock } from '../../views/formatters'
import type { TrafficRecord, TrafficSelection } from './trafficModel'

export type TrafficDock = 'events' | 'dns' | 'flows'
export function TrafficLedger({ records, tab, onTab, selected, onSelect }: { records: TrafficRecord[]; tab: TrafficDock; onTab: (tab: TrafficDock) => void; selected: TrafficSelection | null; onSelect: (selection: TrafficSelection, time?: number) => void }) {
  const [sort, setSort] = useState<{ field: 'time' | 'kind' | 'client' | 'endpoint'; direction: number }>({ field: 'time', direction: 1 })
  const [scroll, setScroll] = useState(0)
  const { ref: scrollRef, height } = useElementSize<HTMLDivElement>()
  const rows = useMemo(() => records.filter(record => tab === 'dns' ? record.selection.kind === 'dns' : tab === 'flows' ? record.selection.kind === 'flow' : true).sort((a, b) => {
    const order = sort.field === 'time' ? a.time - b.time : a[sort.field].localeCompare(b[sort.field], undefined, { numeric: true })
    return order * sort.direction || a.id.localeCompare(b.id)
  }), [records, sort, tab])
  const start = Math.max(0, Math.min(rows.length - 1, Math.floor(scroll / 28) - 3))
  const end = Math.min(rows.length, start + Math.ceil((height || 140) / 28) + 7)
  return <section className="traffic-ledger" aria-label="Traffic evidence ledger"><header><div role="group" aria-label="Evidence ledger tabs">{(['events', 'dns', 'flows'] as const).map(value => <button type="button" key={value} aria-pressed={tab === value} onClick={() => { onTab(value); scrollRef.current?.scrollTo({ top: 0 }); setScroll(0) }}>{value === 'events' ? 'Events' : value === 'dns' ? 'DNS' : 'Flow records'}</button>)}</div><span>{rows.length.toLocaleString()} loaded / filtered records</span></header>
    <div className="ledger-scroll" ref={scrollRef} onScroll={event => setScroll(event.currentTarget.scrollTop)}><div role="table" aria-label="Traffic records" aria-rowcount={rows.length + 1} className="ledger-table">
      <div role="row" className="ledger-columns">{([['time', 'Occurred at'], ['kind', 'Record / flow'], ['client', 'Client'], ['endpoint', 'Endpoint']] as const).map(([field, label]) => <div role="columnheader" key={field} aria-sort={sort.field === field ? sort.direction > 0 ? 'ascending' : 'descending' : 'none'}><button type="button" onClick={() => { setSort({ field, direction: sort.field === field ? -sort.direction : 1 }); scrollRef.current?.scrollTo({ top: 0 }); setScroll(0) }}>{label}{sort.field === field ? sort.direction > 0 ? ' ↑' : ' ↓' : ''}</button></div>)}<div role="columnheader">Provenance</div><div role="columnheader">Detail</div><div role="columnheader">Copy</div></div>
      <div role="rowgroup" className="ledger-row-space" style={{height: rows.length * 28}}>{rows.slice(start, end).map((record,index) => <div role="row" aria-rowindex={start + index + 2} key={record.id} className={`ledger-record ${selected?.kind === record.selection.kind && selected.id === record.selection.id ? 'selected' : ''}`} style={{top:(start + index) * 28}}>
        <div role="cell" className="numeric" title={new Date(record.time).toISOString()}>{formatClock(record.time)}</div><div role="cell" className="pinned-record"><button type="button" title={record.selection.id} onClick={() => onSelect(record.selection, record.time)}>{record.kind} · {record.selection.id}</button></div><div role="cell" className="numeric">{record.client}</div><div role="cell" title={record.endpoint}>{record.endpoint}</div><div role="cell" className={record.provenance === 'Derived' ? 'derived' : ''}>{record.provenance}</div><div role="cell" title={record.detail}>{record.detail}</div><div role="cell"><CopyButton value={JSON.stringify(record.raw, null, 2)} label={`Copy ${record.selection.kind} ${record.selection.id}`} /></div>
      </div>)}</div>
    </div>{rows.length === 0 ? <p className="ledger-empty">No loaded records match this tab and filter.</p> : null}</div>
    <footer>Flow records show lifetime counters; events and DNS retain their source time and provenance.</footer>
  </section>
}
