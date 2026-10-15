import { routeForSeriesAt, routeStateLabel } from '@infrareveal/session-state'
import type { MapWindow } from '@infrareveal/session-state'
import { formatClock } from '../../../views/formatters'
import { GRAPH_NODES, pathForEvent, type GraphNodeId } from '../model/graphLayout'
import type { PipelineEvent } from '../types'
import { CopyButton } from '../../../shared/ui/CopyButton'
export function NodeInspector({ nodeId, events, selectedEvent: event, window, onEvent }: { nodeId: GraphNodeId | null; events: PipelineEvent[]; selectedEvent?: PipelineEvent; window: MapWindow; onEvent: (event: PipelineEvent) => void }) {
  const node = GRAPH_NODES.find(value => value.id === nodeId), summary = event?.summary
  const related = node ? events.filter(value => value.kind !== 'health' && pathForEvent(value).nodes.includes(node.id)) : []
  const chunk = window.series.find(value => value.client_ip === summary?.clientIp && value.destination_ip === summary?.remoteIp && value.protocol === summary?.protocol && value.destination_port === summary?.remotePort && value.start_ms <= (event?.occurredAtMs ?? 0) && value.start_ms + value.chunk_ms > (event?.occurredAtMs ?? 0))
  const route = chunk && event ? routeForSeriesAt(chunk, window.routes, event.occurredAtMs) : null
  const destination = window.destinations.find(value => value.id === chunk?.destination_id)
  return <section className="lab-node-inspector" aria-label="Lab node inspector"><div className="lab-eyebrow">Selected node</div><h2>{node?.label || 'Inspect the path'}</h2><p>{node?.plane === 'observation' ? 'Evidence collected alongside forwarding.' : 'Gateway topology. Intermediate motion illustrates the path; it is not per-packet instrumentation.'}</p>
    {event ? <><dl><dt>Event</dt><dd>{event.kind} / {event.stage}</dd><dt>Client</dt><dd>{summary?.clientIp || 'Unavailable'}</dd><dt>Endpoint</dt><dd>{summary?.remoteIp || 'Unavailable'}:{summary?.remotePort || '—'}</dd><dt>Direction</dt><dd>{event.direction === 'remote_to_client' ? 'Remote → client' : 'Client → remote'}</dd><dt>Occurred</dt><dd>{formatClock(event.occurredAtMs)}</dd><dt>Captured wire</dt><dd>{summary?.wireBytes ?? '—'} B</dd><dt>Payload</dt><dd>{summary?.payloadBytes ?? '—'} B</dd><dt>Packets</dt><dd>{summary?.packetCount ?? '—'}</dd></dl>
      {summary?.verdict && <p>Verdict {summary.verdict} · {summary.verdictSource}</p>}
      {chunk && <p>{chunk.service_label} · {chunk.evidence.source || 'Independent endpoint'} · {chunk.evidence.confidence}{chunk.evidence.ambiguous ? ' · ambiguous' : ''}</p>}
      {nodeId === 'conntrack' && <p>Core aggregates do not retain individual connection state. Raw connection diagnostics are optional.</p>}
      {nodeId === 'enricher' && <p>{destination ? `${destination.provider || 'Provider unknown'} · ${destination.city} ${destination.country}` : 'Location unavailable.'}</p>}
      {nodeId === 'route_worker' && <p>{route ? `${route.method} · ${routeStateLabel(route, event.occurredAtMs)} · ${route.hops.map(hop => hop.missing ? '*' : hop.address).join(' → ')}` : 'No valid route evidence available at this time.'}</p>}
      <details><summary>Source event</summary><CopyButton value={JSON.stringify(event, null, 2)} label="Copy event JSON" /><pre>{JSON.stringify(event, null, 2)}</pre></details>
    </> : <p>Select an event to inspect observed evidence.</p>}
    <details className="lab-related"><summary>{related.length} related events</summary>{related.slice(-80).map(value => <button key={value.id} onClick={() => onEvent(value)}>{value.kind} · {formatClock(value.occurredAtMs)}</button>)}</details>
  </section>
}
