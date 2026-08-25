import { describe, expect, it } from 'vitest'
import type { FlowActivityChunk, GatewayData } from '../data/types'
import { buildSessionComposition, decodeActivityChunk } from './sessionModel'

const chunkStart = '2026-08-25T14:00:00.000Z'

function chunk(overrides: Partial<FlowActivityChunk> = {}): FlowActivityChunk {
  return {
    id: 'chunk-1', session: 'session-1', flow: 'flow-1', flow_key: 'flow-key',
    chunk_start: chunkStart, bucket_ms: 50, chunk_ms: 5000,
    samples: { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[0, 420, 0, 3, 0], [50, 0, 16384, 0, 12]] },
    wire_bytes_out: 600, wire_bytes_in: 17000, payload_bytes_out: 420,
    payload_bytes_in: 16384, packets_out: 3, packets_in: 12,
    tcp_flags_out: 24, tcp_flags_in: 24, capture_complete: true,
    dropped_events: 0, updated_at_source: chunkStart, ...overrides,
  }
}

function gatewayData(activityChunk: FlowActivityChunk): GatewayData {
  return {
    sessions: [{ id: 'session-1', created: chunkStart, updated: chunkStart, name: 'Test', active: true }],
    selectedSession: { id: 'session-1', created: chunkStart, updated: chunkStart, name: 'Test', active: true },
    flows: [{
      id: 'flow-1', created: chunkStart, updated: chunkStart, session: 'session-1',
      client_ip: '10.0.0.50', destination_ip: '93.184.216.34', source_port: 53000,
      destination_port: 443, protocol: 'tcp', state: 'ESTABLISHED', start: chunkStart,
      last_seen: '2026-08-25T14:00:02.000Z', bytes_out: 600, bytes_in: 17000,
      packets_out: 3, packets_in: 12,
    }],
    dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [],
    flowActivityChunks: [activityChunk],
    flowActivityWindows: [{ id: 'window-1', session: 'session-1', window_key: 'session-1|window', window_start: chunkStart, window_ms: 5000, capture_running: true, capture_complete: true, dropped_events: 0, last_error: '' }],
    flowActivityStatuses: [], destinations: [], routes: [],
  }
}

describe('flow activity model', () => {
  it('decodes sparse directional samples and derives non-overlapping active time', () => {
    const composition = buildSessionComposition(gatewayData(chunk()))
    expect(composition.clips[0].activity.samples).toHaveLength(2)
    expect(composition.clips[0].activity.activeMs).toBe(100)
    expect(composition.clips[0].activity.idleMs).toBe(1900)
    expect(composition.clips[0].activity.payloadBytesIn).toBe(16384)
    expect(composition.clips[0].activity.captureComplete).toBe(true)
    expect(composition.clips[0].activity.completeRanges).toEqual([{
      startMs: Date.parse(chunkStart),
      endMs: Date.parse('2026-08-25T14:00:02.000Z'),
    }])
  })

  it.each([
    { version: 2, bucket_ms: 50, chunk_ms: 5000, samples: [[0, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: -50, chunk_ms: 5000, samples: [[0, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[5000, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[0, -1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [['bad', 1, 0, 1, 0]] },
  ])('ignores malformed or out-of-range JSON %#', (samples) => {
    expect(decodeActivityChunk(chunk({ samples }))).toEqual([])
  })

  it('ignores activity chunks whose parent flow is not displayable', () => {
    const data = gatewayData(chunk({ flow: 'missing-flow' }))
    expect(buildSessionComposition(data).clips[0].activity.samples).toEqual([])
  })

  it('does not call uncovered time idle', () => {
    const data = gatewayData(chunk({ capture_complete: false, dropped_events: 2 }))
    data.flowActivityWindows = []
    const activity = buildSessionComposition(data).clips[0].activity
    expect(activity.activeMs).toBe(100)
    expect(activity.idleMs).toBe(0)
    expect(activity.captureComplete).toBe(false)
  })

  it('counts a bucket with both directions only once as active time', () => {
    const bothDirections = chunk({
      samples: { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[0, 100, 200, 1, 2]] },
    })
    expect(buildSessionComposition(gatewayData(bothDirections)).clips[0].activity.activeMs).toBe(50)
  })
})
