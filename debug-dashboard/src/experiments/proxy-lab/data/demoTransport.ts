import { DEMO_EPOCH_MS, DEMO_SESSION_ID } from '../constants'
import type { PipelineEvent, PipelineStreamEnvelope } from '../types'

const flowKey = 'tcp|10.42.0.18|53120|142.250.74.14|443'

export const demoPipelineEvents: PipelineEvent[] = [
  event('dns-in', 1, 0, 'dns', 'gateway_ingress', { protocol: 'udp', clientIp: '10.42.0.18', clientPort: 58722, remoteIp: '10.42.0.1', remotePort: 53, dnsName: 'example.org', dnsType: 'A' }),
  event('dns-resolved', 2, 260, 'dns', 'dns', { clientIp: '10.42.0.18', dnsName: 'example.org', dnsType: 'A', hostname: 'example.org' }, 'derived'),
  event('tcp-arrived', 3, 700, 'flow', 'gateway_ingress', { protocol: 'tcp', clientIp: '10.42.0.18', clientPort: 53120, remoteIp: '142.250.74.14', remotePort: 443, flowKey, packetCount: 1, tcpFlags: 2 }),
  event('tcp-queued', 4, 710, 'gate', 'gate_queue', { protocol: 'tcp', clientIp: '10.42.0.18', clientPort: 53120, remoteIp: '142.250.74.14', remotePort: 443, flowKey, packetCount: 1 }),
  event('tcp-approved', 5, 3_700, 'gate', 'forward', { flowKey, verdict: 'approved', verdictSource: 'operator', packetCount: 1 }),
  event('tcp-burst-out', 6, 3_750, 'burst', 'header_capture', { protocol: 'tcp', flowKey, wireBytes: 2_740, payloadBytes: 2_212, packetCount: 6 }, 'observed', 'client_to_remote'),
  event('tcp-nat', 7, 3_770, 'flow', 'nat', { protocol: 'tcp', flowKey, packetCount: 6 }, 'derived', 'client_to_remote'),
  event('tcp-burst-in', 8, 4_100, 'burst', 'gateway_ingress', { protocol: 'tcp', flowKey, wireBytes: 16_420, payloadBytes: 15_780, packetCount: 13 }, 'observed', 'remote_to_client'),
  event('quic-drop', 9, 4_800, 'gate', 'gate_queue', { protocol: 'udp', clientIp: '10.42.0.21', clientPort: 49831, remoteIp: '172.217.16.142', remotePort: 443, verdict: 'rejected', verdictSource: 'operator', packetCount: 1 }),
  event('attribution', 10, 5_300, 'attribution', 'attribution', { flowKey, hostname: 'example.org', confidence: 'high' }, 'derived'),
  event('destination', 11, 5_900, 'destination', 'destination', { flowKey, hostname: 'edge.example.org', confidence: 'medium' }, 'derived'),
  event('route', 12, 6_600, 'route', 'route', { protocol: 'icmp', remoteIp: '142.250.74.14', hostname: 'edge.example.org' }, 'derived'),
  event('capture-gap', 13, 7_400, 'health', 'health', { droppedEvents: 37, captureComplete: false }),
]

export const demoPipelineEnvelope: PipelineStreamEnvelope = {
  version: 1,
  sessionId: DEMO_SESSION_ID,
  events: demoPipelineEvents,
  droppedEvents: 37,
  serverNowMs: DEMO_EPOCH_MS + 8_000,
}

export function isProxyLabDemoEnabled(search: string, development: boolean, configured: string | undefined) {
  if (configured === 'true') return true
  return development && new URLSearchParams(search).get('demo') === '1'
}

function event(
  id: string,
  sequence: number,
  offsetMs: number,
  kind: PipelineEvent['kind'],
  stage: PipelineEvent['stage'],
  summary: PipelineEvent['summary'],
  timing: PipelineEvent['timing'] = 'observed',
  direction?: PipelineEvent['direction'],
): PipelineEvent {
  return {
    id: `demo-${id}`,
    sequence,
    sessionId: DEMO_SESSION_ID,
    traceId: `demo-trace-${String(sequence).padStart(3, '0')}`,
    kind,
    stage,
    direction,
    occurredAtMs: DEMO_EPOCH_MS + offsetMs,
    processedAtMs: DEMO_EPOCH_MS + offsetMs + (timing === 'observed' ? 2 : 0),
    timing,
    summary,
  }
}
