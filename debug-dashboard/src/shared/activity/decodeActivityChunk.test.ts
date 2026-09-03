import { describe, expect, it } from 'vitest'
import type { FlowActivityChunk } from '@infrareveal/session-state'
import { decodeActivityChunk } from './decodeActivityChunk'

const chunkStart = '2026-08-25T14:00:00.000Z'

function chunk(samples: unknown): FlowActivityChunk {
  return {
    id: 'chunk-1', session: 'session-1', flow: 'flow-1', flow_key: 'flow-key',
    chunk_start: chunkStart, bucket_ms: 50, chunk_ms: 5000, samples,
    wire_bytes_out: 600, wire_bytes_in: 17000, payload_bytes_out: 420,
    payload_bytes_in: 16384, packets_out: 3, packets_in: 12,
    tcp_flags_out: 24, tcp_flags_in: 24, capture_complete: true,
    dropped_events: 0, updated_at_source: chunkStart,
  }
}

describe('decodeActivityChunk', () => {
  it('decodes sparse directional samples', () => {
    expect(decodeActivityChunk(chunk({
      version: 1,
      bucket_ms: 50,
      chunk_ms: 5000,
      samples: [[0, 420, 0, 3, 0], [50, 0, 16384, 0, 12]],
    }))).toEqual([
      { startMs: Date.parse(chunkStart), durationMs: 50, payloadBytesOut: 420, payloadBytesIn: 0, packetsOut: 3, packetsIn: 0, complete: true },
      { startMs: Date.parse(chunkStart) + 50, durationMs: 50, payloadBytesOut: 0, payloadBytesIn: 16384, packetsOut: 0, packetsIn: 12, complete: true },
    ])
  })

  it.each([
    { version: 2, bucket_ms: 50, chunk_ms: 5000, samples: [[0, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: -50, chunk_ms: 5000, samples: [[0, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[5000, 1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [[0, -1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: [['bad', 1, 0, 1, 0]] },
    { version: 1, bucket_ms: 50, chunk_ms: 5000, samples: 'not-an-array' },
  ])('ignores malformed or out-of-range JSON %#', (samples) => {
    expect(decodeActivityChunk(chunk(samples))).toEqual([])
  })
})
