import type {
  DNSQuery,
  Destination,
  Flow,
  FlowActivityChunk,
  FlowAttribution,
  GateEvent,
  GatewayData,
  Route,
} from '@infrareveal/session-state'
import { decodeActivityChunk } from '../../../shared/activity/decodeActivityChunk'
import type { PipelineDirection, PipelineEvent, PipelineEventSummary } from '../types'

export type RecordedEventRange = { fromMs: number; toMs: number }

type RevisionRecord = { id: string; created?: string; updated?: string }
type CacheEntry = { revision: string; events: PipelineEvent[] }

/** Preserves projections for unchanged PocketBase revisions and drops detail
 * cache entries as soon as the shared runtime evicts their source records. */
export class RecordedEventProjector {
  private readonly cache = new Map<string, CacheEntry>()

  project(data: GatewayData, gateEvents: GateEvent[], range: RecordedEventRange) {
    return projectRecordedEvents(data, gateEvents, range, this.cache)
  }

  clear() {
    this.cache.clear()
  }

  get cacheSize() {
    return this.cache.size
  }
}

export function projectRecordedEvents(
  data: GatewayData,
  gateEvents: GateEvent[],
  range: RecordedEventRange,
  cache = new Map<string, CacheEntry>(),
): PipelineEvent[] {
  if (!Number.isFinite(range.fromMs) || !Number.isFinite(range.toMs) || range.toMs <= range.fromMs) return []

  const seenCacheKeys = new Set<string>()
  const flowById = new Map(data.flows.map((flow) => [flow.id, flow]))
  const relevantDestinationIPs = new Set(data.flows.map((flow) => flow.destination_ip))
  const events: PipelineEvent[] = []

  const cached = <T extends RevisionRecord>(prefix: string, record: T, extraRevision: string, build: () => PipelineEvent[]) => {
    const key = `${prefix}:${record.id}`
    seenCacheKeys.add(key)
    const revision = `${recordRevision(record)}|${extraRevision}`
    const previous = cache.get(key)
    if (previous?.revision === revision) return previous.events
    const projected = build()
    cache.set(key, { revision, events: projected })
    return projected
  }

  for (const flow of data.flows) {
    events.push(...cached('flow', flow, '', () => projectFlow(flow)))
  }
  for (const chunk of data.flowActivityChunks) {
    const flow = flowById.get(chunk.flow)
    if (!flow) continue
    events.push(...cached('chunk', chunk, recordRevision(flow), () => projectActivityChunk(chunk, flow)))
  }
  for (const query of data.dnsQueries) {
    events.push(...cached('dns', query, '', () => projectDNS(query)))
  }
  for (const attribution of data.attributions) {
    const flow = flowById.get(attribution.flow)
    events.push(...cached('attribution', attribution, recordRevision(flow), () => projectAttribution(attribution, flow)))
  }
  for (const destination of data.destinations) {
    if (!relevantDestinationIPs.has(destination.ip)) continue
    events.push(...cached('destination', destination, '', () => projectDestination(destination, data.selectedSession?.id)))
  }
  for (const route of data.routes) {
    events.push(...cached('route', route, '', () => projectRoute(route)))
  }
  for (const gateEvent of gateEvents) {
    events.push(...cached('gate', gateEvent, '', () => projectGateEvent(gateEvent)))
  }

  for (const key of cache.keys()) {
    if (!seenCacheKeys.has(key)) cache.delete(key)
  }

  return events
    .filter((event) => event.occurredAtMs >= range.fromMs && event.occurredAtMs < range.toMs)
    .sort(comparePipelineEvents)
}

export function comparePipelineEvents(left: PipelineEvent, right: PipelineEvent) {
  return left.occurredAtMs - right.occurredAtMs || left.sequence - right.sequence || left.id.localeCompare(right.id)
}

function projectFlow(flow: Flow): PipelineEvent[] {
  const occurredAtMs = timestamp(flow.start || flow.created)
  if (occurredAtMs === null) return []
  const flowKey = keyForFlow(flow)
  return [recordedEvent({
    id: `flow:${flow.id}:discovered`, sessionId: flow.session, traceId: `flow:${flow.id}`,
    kind: 'flow', stage: 'conntrack', direction: 'client_to_remote', occurredAtMs, timing: 'observed',
    processedAtMs: timestamp(flow.created) ?? undefined,
    summary: flowSummary(flow, flowKey),
  })]
}

function projectActivityChunk(chunk: FlowActivityChunk, flow: Flow): PipelineEvent[] {
  const flowKey = chunk.flow_key || keyForFlow(flow)
  const events: PipelineEvent[] = []
  decodeActivityChunk(chunk).forEach((sample) => {
    if (sample.payloadBytesOut > 0 || sample.packetsOut > 0) {
      events.push(activityEvent(chunk, flow, flowKey, sample.startMs, 'client_to_remote', sample.payloadBytesOut, sample.packetsOut, sample.complete))
    }
    if (sample.payloadBytesIn > 0 || sample.packetsIn > 0) {
      events.push(activityEvent(chunk, flow, flowKey, sample.startMs, 'remote_to_client', sample.payloadBytesIn, sample.packetsIn, sample.complete))
    }
  })
  return events
}

function activityEvent(
  chunk: FlowActivityChunk,
  flow: Flow,
  flowKey: string,
  occurredAtMs: number,
  direction: PipelineDirection,
  payloadBytes: number,
  packetCount: number,
  captureComplete: boolean,
) {
  const offset = occurredAtMs - (timestamp(chunk.chunk_start) ?? occurredAtMs)
  return recordedEvent({
    id: `activity:${chunk.id}:${offset}:${direction}`,
    sessionId: chunk.session,
    traceId: `flow:${flow.id}`,
    kind: 'burst', stage: 'header_capture', direction, occurredAtMs, timing: 'observed',
    processedAtMs: timestamp(chunk.updated_at_source || chunk.updated) ?? undefined,
    summary: {
      ...flowSummary(flow, flowKey), payloadBytes, packetCount, captureComplete,
      tcpFlags: direction === 'client_to_remote' ? chunk.tcp_flags_out : chunk.tcp_flags_in,
    },
  })
}

function projectDNS(query: DNSQuery): PipelineEvent[] {
  const occurredAtMs = timestamp(query.timestamp)
  if (occurredAtMs === null) return []
  const traceId = `dns:${query.id}`
  const summary: PipelineEventSummary = {
    protocol: 'udp', clientIp: query.client_ip, remotePort: 53,
    dnsName: query.query_name, dnsType: query.query_type,
  }
  const events = [recordedEvent({
    id: `${traceId}:query`, sessionId: query.session, traceId, kind: 'dns', stage: 'dns',
    direction: 'client_to_remote', occurredAtMs, processedAtMs: timestamp(query.created) ?? undefined,
    timing: 'observed', summary,
  })]
  if ((query.answers?.length ?? 0) > 0) {
    events.push(recordedEvent({
      id: `${traceId}:answer`, sessionId: query.session, traceId, parentId: `${traceId}:query`,
      kind: 'dns', stage: 'dns', direction: 'remote_to_client',
      occurredAtMs: timestamp(query.updated) ?? occurredAtMs, timing: 'derived',
      summary,
    }))
  }
  return events
}

function projectAttribution(attribution: FlowAttribution, flow?: Flow): PipelineEvent[] {
  const occurredAtMs = timestamp(attribution.observed_at)
  if (occurredAtMs === null) return []
  return [recordedEvent({
    id: `attribution:${attribution.id}`, sessionId: attribution.session,
    traceId: flow ? `flow:${flow.id}` : `attribution:${attribution.id}`,
    kind: 'attribution', stage: 'attribution', occurredAtMs, timing: 'derived',
    processedAtMs: timestamp(attribution.created) ?? undefined,
    summary: {
      ...(flow ? flowSummary(flow, keyForFlow(flow)) : {}),
      hostname: attribution.candidate_hostname || undefined,
      confidence: attribution.confidence,
    },
  })]
}

function projectDestination(destination: Destination, sessionId?: string): PipelineEvent[] {
  const occurredAtMs = timestamp(destination.last_seen)
  if (occurredAtMs === null || !sessionId) return []
  return [recordedEvent({
    id: `destination:${destination.id}`, sessionId, traceId: `destination:${destination.ip}`,
    kind: 'destination', stage: 'destination', occurredAtMs, timing: 'derived',
    summary: { remoteIp: destination.ip, hostname: destination.reverse_dns || undefined },
  })]
}

function projectRoute(route: Route): PipelineEvent[] {
  const occurredAtMs = timestamp(route.completed_at)
  if (occurredAtMs === null) return []
  return [recordedEvent({
    id: `route:${route.id}`, sessionId: route.session, traceId: `route:${route.id}`,
    kind: 'route', stage: 'route', occurredAtMs, timing: 'observed',
    summary: { protocol: route.protocol, remoteIp: route.destination_ip, remotePort: validPort(route.destination_port) },
  })]
}

function projectGateEvent(gate: GateEvent): PipelineEvent[] {
  const queuedAtMs = timestamp(gate.queued_at)
  if (queuedAtMs === null) return []
  const traceId = `gate:${gate.decision_id}`
  const summary: PipelineEventSummary = {
    protocol: gate.protocol, clientIp: gate.client_ip, clientPort: validPort(gate.source_port),
    remoteIp: gate.destination_ip, remotePort: validPort(gate.destination_port),
    flowKey: gate.flow_key, packetCount: Math.max(0, gate.packet_count), wireBytes: gate.wire_bytes,
    payloadBytes: gate.payload_bytes, tcpFlags: gate.tcp_flags,
  }
  const events = [recordedEvent({
    id: `${traceId}:queued`, sessionId: gate.session, traceId, kind: 'gate', stage: 'gate_queue',
    direction: gate.direction ?? 'client_to_remote', occurredAtMs: queuedAtMs, timing: 'observed', summary,
  })]
  if (gate.state !== 'queued') {
    events.push(recordedEvent({
      id: `${traceId}:verdict`, sessionId: gate.session, traceId, parentId: `${traceId}:queued`,
      kind: 'gate', stage: gate.state === 'rejected' ? 'gate_queue' : 'forward',
      direction: gate.direction ?? 'client_to_remote', occurredAtMs: timestamp(gate.decided_at) ?? queuedAtMs + Math.max(0, gate.wait_ms),
      timing: 'observed', summary: { ...summary, verdict: gate.state, verdictSource: gate.verdict_source },
    }))
  }
  return events
}

function recordedEvent(event: Omit<PipelineEvent, 'sequence'>): PipelineEvent {
  return { sequence: 0, ...event }
}

function flowSummary(flow: Flow, flowKey: string): PipelineEventSummary {
  return {
    protocol: flow.protocol.toLowerCase(), clientIp: flow.client_ip,
    clientPort: validPort(flow.source_port), remoteIp: flow.destination_ip,
    remotePort: validPort(flow.destination_port), flowKey,
  }
}

function keyForFlow(flow: Flow) {
  return `${flow.protocol.toLowerCase()}|${flow.client_ip}|${flow.source_port}|${flow.destination_ip}|${flow.destination_port}`
}

function validPort(port: number) {
  return Number.isInteger(port) && port > 0 && port <= 65_535 ? port : undefined
}

function timestamp(value?: string) {
  if (!value) return null
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : null
}

function recordRevision(record?: RevisionRecord) {
  if (!record) return ''
  return record.updated || record.created || JSON.stringify(record)
}
