import { formatClock } from '../../../views/formatters'
import type { GatewayData } from '@infrareveal/session-state'
import { GRAPH_NODES, pathForEvent, type GraphNodeId } from '../model/graphLayout'
import type { PipelineEvent } from '../types'
import { CopyButton } from '../../../shared/ui/CopyButton'

export function NodeInspector({ nodeId, events, selectedEvent, data, onEvent }: { nodeId: GraphNodeId | null; events: PipelineEvent[]; selectedEvent?: PipelineEvent; data: GatewayData; onEvent: (event: PipelineEvent) => void }) {
  const node = GRAPH_NODES.find(n => n.id === nodeId)
  const related = node ? events.filter(e => e.kind !== 'health' && (pathForEvent(e).nodes.includes(node.id) || node.id === 'header_capture' && e.kind === 'burst')) : []
  const event = selectedEvent
  const summary = event?.summary
  const flow = summary?.flowKey ? data.flows.find(f => [f.protocol.toLowerCase(), f.client_ip, f.source_port, f.destination_ip, f.destination_port].join('|') === summary.flowKey) : undefined
  const destination = data.destinations.find(d => d.ip === summary?.remoteIp)
  const route = data.routes.find(r => r.destination_ip === summary?.remoteIp)
  const dns = data.dnsQueries.filter(q => q.client_ip === summary?.clientIp && (q.query_name === summary?.dnsName || q.query_name === summary?.hostname || q.answers?.includes(summary?.remoteIp || '')))
  return <section className="lab-node-inspector" aria-label="Lab node inspector"><div className="lab-eyebrow">Selected node</div><h2>{node?.label || 'Inspect the path'}</h2><p>{!node ? 'Select a node or step along the selected event’s path.' : node.plane === 'observation' ? 'Observation and enrichment provide evidence alongside forwarding.' : 'This node is part of the gateway’s traffic path.'}</p>
    {event ? <><dl><dt>Event</dt><dd>{event.kind} / {event.stage}</dd><dt>Timing</dt><dd className={event.timing === 'derived' ? 'derived' : ''}>{event.timing === 'derived' ? 'Derived · reconstructed' : 'Observed'}</dd><dt>Client</dt><dd>{summary?.clientIp || 'Unavailable'}{summary?.clientPort ? `:${summary.clientPort}` : ''}</dd><dt>Endpoint</dt><dd>{summary?.remoteIp || 'Unavailable'}{summary?.remotePort ? `:${summary.remotePort}` : ''}</dd><dt>Direction</dt><dd>{event.direction === 'remote_to_client' ? 'Remote → client' : event.direction === 'client_to_remote' ? 'Client → remote' : 'Observation branch'}</dd><dt>Occurred</dt><dd title={new Date(event.occurredAtMs).toISOString()}>{formatClock(event.occurredAtMs)}</dd><dt>Processed</dt><dd>{event.processedAtMs ? formatClock(event.processedAtMs) : 'Not recorded'}</dd><dt>Sequence</dt><dd>{event.sequence}</dd></dl>
      {(nodeId === 'flow_gate' || nodeId === 'dns_gate' || nodeId === 'drop') ? <p className="lab-path-evidence">{summary?.verdict ? `Verdict: ${summary.verdict} · ${summary.verdictSource || 'source unavailable'}` : event.kind === 'gate' ? 'This source event records a hold. Its path ends at the gate; later forwarding requires separate verdict evidence.' : 'No gate verdict is attached to this event. The forwarding path is explanatory.'}</p> : null}
      {nodeId === 'conntrack' && flow ? <dl><dt>State</dt><dd>{flow.state}</dd><dt>Lifetime in / out</dt><dd>{flow.bytes_in} / {flow.bytes_out} B</dd></dl> : null}
      {nodeId === 'header_capture' ? <dl><dt>Payload</dt><dd>{summary?.payloadBytes ?? 'Not recorded'} B</dd><dt>Wire</dt><dd>{summary?.wireBytes ?? 'Not recorded'} B</dd><dt>Packets</dt><dd>{summary?.packetCount ?? 'Not recorded'}</dd></dl> : null}
      {nodeId === 'dnsmasq' || nodeId === 'correlator' ? <><p>{summary?.hostname || summary?.dnsName || 'No hostname evidence attached'} · {summary?.confidence || 'Confidence not recorded'}</p>{dns.slice(0, 8).map(q => <p className="lab-raw-note" key={q.id}>{q.query_name} ({q.query_type}) → {q.answers?.join(', ') || 'No answers'}{q.aliases?.length ? ` · aliases: ${q.aliases.join(', ')}` : ''}</p>)}</> : null}
      {nodeId === 'enricher' ? <p>{destination ? `${destination.organization || destination.provider_label || 'Provider unknown'} · AS${destination.asn || '—'} · ${destination.city} ${destination.country}` : 'Destination enrichment is unavailable for this endpoint.'}</p> : null}
      {nodeId === 'route_worker' ? <><p className="lab-path-evidence">Gateway approximation. Probe times do not measure the client application’s latency or packet path.</p><p>{route ? `${route.method} · ${route.complete ? 'Complete' : 'Incomplete'} · ${route.hops?.map(h => h.missing ? '*' : h.address).join(' → ') || route.error}` : 'No route probe is available.'}</p></> : null}
      <details><summary>Source record &amp; provenance</summary><CopyButton value={JSON.stringify(event, null, 2)} label="Copy Lab event JSON" /><pre>{JSON.stringify(event, null, 2)}</pre>{flow ? <><CopyButton value={JSON.stringify(flow, null, 2)} label="Copy Lab flow JSON" /><pre>{JSON.stringify(flow, null, 2)}</pre></> : null}</details>
    </> : <p>No source event selected. The diagram shows the gateway topology.</p>}
    <details className="lab-related"><summary>{related.length} related events in selected trace</summary>{related.slice(-80).map(e => <button type="button" aria-pressed={e.id === event?.id} key={e.id} onClick={() => onEvent(e)}>{e.kind} · {e.stage}<span>{formatClock(e.occurredAtMs)} · {e.timing}</span></button>)}{related.length > 80 ? <p>Showing the latest 80 loaded events.</p> : null}</details>
  </section>
}
