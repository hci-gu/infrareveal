import { describe, expect, it } from 'vitest'
import type { Flow, GatewayData } from '@infrareveal/session-state'
import type { PipelineEvent } from '../types'
import { RecordedEventProjector, comparePipelineEvents, projectRecordedEvents } from './projectRecordedEvents'

const start = '2026-09-02T12:00:00.000Z'
const startMs = Date.parse(start)

describe('recorded event projection', () => {
  it('is deterministic, preserves the canonical key, and splits bidirectional buckets', () => {
    const data = gatewayData()
    const range = { fromMs: startMs - 1, toMs: startMs + 10_000 }
    const first = projectRecordedEvents(data, [], range)
    const second = projectRecordedEvents(data, [], range)

    expect(second).toEqual(first)
    expect(first.find((event) => event.id === 'flow:flow-1:discovered')?.summary).toMatchObject({
      flowKey: 'tcp|10.42.0.18|53120|142.250.74.14|443',
    })
    expect(first.find((event) => event.id === 'flow:flow-1:discovered')?.summary).not.toHaveProperty('hostname')
    expect(first.filter((event) => event.kind === 'burst').map((event) => event.direction)).toEqual([
      'client_to_remote', 'remote_to_client',
    ])
    expect(first.some((event) => event.kind === 'health')).toBe(false)
  })

  it('retains unchanged cached projections and evicts missing detail records', () => {
    const projector = new RecordedEventProjector()
    const data = gatewayData()
    const range = { fromMs: startMs - 1, toMs: startMs + 10_000 }
    const first = projector.project(data, [], range)
    const second = projector.project(data, [], range)
    expect(second.find((event) => event.id === 'flow:flow-1:discovered'))
      .toBe(first.find((event) => event.id === 'flow:flow-1:discovered'))

    const withoutDetail = { ...data, flowActivityChunks: [], flowActivityWindows: [] }
    projector.project(withoutDetail, [], range)
    expect(projector.cacheSize).toBeLessThan(data.flows.length + data.flowActivityChunks.length + data.flowActivityWindows.length)
  })

  it('sorts identical timestamps by sequence and then ID', () => {
    const events = [event('z', 2), event('b', 1), event('a', 1)].sort(comparePipelineEvents)
    expect(events.map((item) => item.id)).toEqual(['a', 'b', 'z'])
  })
})

function gatewayData(): GatewayData {
  const flow: Flow = {
    id: 'flow-1', created: start, updated: start, session: 'session-1',
    client_ip: '10.42.0.18', destination_ip: '142.250.74.14', source_port: 53120,
    destination_port: 443, protocol: 'TCP', state: 'ESTABLISHED', start,
    last_seen: '2026-09-02T12:00:03.000Z', bytes_out: 100, bytes_in: 200,
    packets_out: 1, packets_in: 2,
  }
  return {
    sessions: [{ id: 'session-1', created: start, updated: start, name: 'Test', active: false }],
    selectedSession: { id: 'session-1', created: start, updated: start, name: 'Test', active: false },
    flows: [flow], dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [],
    flowActivityChunks: [{
      id: 'chunk-1', created: start, updated: start, session: 'session-1', flow: 'flow-1',
      flow_key: 'tcp|10.42.0.18|53120|142.250.74.14|443', chunk_start: start,
      bucket_ms: 50, chunk_ms: 5000,
      samples: { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[0, 100, 200, 1, 2]] },
      wire_bytes_out: 120, wire_bytes_in: 220, payload_bytes_out: 100, payload_bytes_in: 200,
      packets_out: 1, packets_in: 2, tcp_flags_out: 2, tcp_flags_in: 18,
      capture_complete: false, dropped_events: 2, updated_at_source: start,
    }],
    flowActivityWindows: [{
      id: 'window-1', created: start, updated: start, session: 'session-1', window_key: 'window-1',
      window_start: start, window_ms: 5000, capture_running: true, capture_complete: false,
      dropped_events: 2, last_error: '',
    }],
    flowActivityStatuses: [], destinations: [], routes: [], gateEvents: [],
  }
}

function event(id: string, sequence: number): PipelineEvent {
  return {
    id, sequence, sessionId: 'session-1', traceId: 'trace', kind: 'health', stage: 'health',
    occurredAtMs: startMs, timing: 'observed', summary: {},
  }
}
