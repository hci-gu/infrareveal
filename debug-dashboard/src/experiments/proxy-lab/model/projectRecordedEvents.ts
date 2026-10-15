import { captureQuality, seriesKey } from '@infrareveal/session-state'
import type { MapWindow } from '@infrareveal/session-state'
import type { PipelineEvent } from '../types'
/** Core traffic describes aggregate capture bursts; it cannot reconstruct sockets or conntrack discovery. */
export function projectRecordedEvents(window: MapWindow): PipelineEvent[] {
  const bursts = new Map<string, PipelineEvent>()
  for (const chunk of window.series) for (const sample of chunk.samples) {
    const occurredAtMs = Math.floor((chunk.start_ms + sample[0]) / 500) * 500
    for (const direction of ['client_to_remote', 'remote_to_client'] as const) {
      const outgoing = direction === 'client_to_remote'
      const wireBytes = sample[outgoing ? 1 : 2], payloadBytes = sample[outgoing ? 3 : 4], packetCount = sample[outgoing ? 5 : 6]
      if (wireBytes === 0 && packetCount === 0) continue
      const traceId = `series:${seriesKey(chunk)}`, id = `${traceId}:${occurredAtMs}:${direction}`
      const previous = bursts.get(id)
      if (previous) { previous.summary.wireBytes! += wireBytes; previous.summary.payloadBytes! += payloadBytes; previous.summary.packetCount! += packetCount; continue }
      bursts.set(id, { id, sequence: 0, sessionId: chunk.session, traceId, kind: 'burst', stage: 'header_capture', direction, occurredAtMs, timing: 'observed', summary: { clientIp: chunk.client_ip, remoteIp: chunk.destination_ip, remotePort: chunk.destination_port, protocol: chunk.protocol, hostname: chunk.service_label || chunk.evidence.hostname, confidence: chunk.evidence.confidence, wireBytes, payloadBytes, packetCount, captureComplete: captureQuality(window.coverage, occurredAtMs, occurredAtMs+500) === 'complete' } })
    }
  }
  const routes: PipelineEvent[] = window.routes.filter(route => route.available_ms >= window.from_ms && route.available_ms < window.to_ms).map(route => ({ id: `route:${route.id}`, sequence: 0, sessionId: route.session, traceId: `route:${route.id}`, kind: 'route', stage: 'route', occurredAtMs: route.available_ms, timing: 'observed', summary: { remoteIp: route.destination_ip, remotePort: route.destination_port, protocol: route.protocol, hostname: route.kind === 'network_invalidated' ? 'Network invalidated' : undefined } }))
  return [...bursts.values(), ...routes].sort(comparePipelineEvents)
}
export function comparePipelineEvents(a: PipelineEvent, b: PipelineEvent) { return a.occurredAtMs-b.occurredAtMs || a.sequence-b.sequence || a.id.localeCompare(b.id) }
