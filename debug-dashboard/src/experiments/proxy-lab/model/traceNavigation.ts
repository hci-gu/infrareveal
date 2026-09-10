import type { PipelineEvent } from '../types'
import { pathForEvent, type GraphNodeId, type PathDefinition } from './graphLayout'

export type LabTrace = { id: string; label: string; client: string; protocol: string; events: PipelineEvent[] }
export function traceKey(event: PipelineEvent) { return event.summary.flowKey || event.traceId }
export function buildLabTraces(events: readonly PipelineEvent[]): LabTrace[] {
  const traces = new Map<string, LabTrace>()
  for (const event of events) {
    if (event.kind === 'health') continue
    const id = traceKey(event), summary = event.summary
    const trace = traces.get(id) ?? { id, label: '', client: '', protocol: '', events: [] }
    trace.events.push(event)
    trace.client ||= summary.clientIp || ''
    trace.protocol ||= summary.protocol || ''
    if (!trace.label || summary.remoteIp) trace.label = `${summary.protocol?.toUpperCase() || event.kind} · ${summary.remoteIp ? `${summary.remoteIp}:${summary.remotePort ?? '—'}` : summary.dnsName || summary.hostname || id}`
    traces.set(id, trace)
  }
  for (const trace of traces.values()) trace.events.sort((a, b) => a.occurredAtMs - b.occurredAtMs || a.sequence - b.sequence || a.id.localeCompare(b.id))
  return [...traces.values()].sort((a, b) => Number(!a.client) - Number(!b.client) || a.client.localeCompare(b.client) || a.label.localeCompare(b.label) || a.id.localeCompare(b.id))
}

/** The selected source event defines the path. A queued event ends at its gate. */
export function traceEventPath(event: PipelineEvent | undefined): PathDefinition | null {
  return event && event.kind !== 'health' ? pathForEvent(event) : null
}
export function preferredTraceEvent(trace: LabTrace | undefined, cursorMs: number): PipelineEvent | undefined {
  if (!trace) return
  const atCursor = trace.events.filter(e => e.occurredAtMs <= cursorMs)
  const candidates = atCursor.length ? atCursor : trace.events.slice(0, 1)
  // Gate state is more informative than an unrelated later enrichment event.
  return candidates.filter(e => e.kind === 'gate').slice(-1)[0] ?? candidates.filter(e => e.kind === 'flow' || e.kind === 'burst' || e.kind === 'dns').slice(-1)[0] ?? candidates.slice(-1)[0]
}
export function stepTraceNode(path: PathDefinition | null, selected: GraphNodeId | null, delta: -1 | 1): GraphNodeId | null {
  if (!path?.nodes.length) return null
  const index = selected ? path.nodes.indexOf(selected) : -1
  return path.nodes[Math.min(path.nodes.length - 1, Math.max(0, index < 0 ? delta > 0 ? 0 : path.nodes.length - 1 : index + delta))]
}
