import { expect, it } from 'vitest'
import type { TrafficChunk } from '@infrareveal/session-state'
import { feedLines, feedRate, mergeFeed } from './liveFeed'

const chunk = (id: string, start: number, samples: TrafficChunk['samples'], extra: Partial<TrafficChunk> = {}) => ({
  id, session: 's', capture_epoch: 'e', client_id: 'c1', client_ip: '10.0.0.2', service_key: 'svt.se', service_label: 'svt.se',
  destination_id: 'd', destination_ip: '1.2.3.4', protocol: 'tcp', destination_port: 443, network_epoch: 'n', start_ms: start,
  bucket_ms: 50, chunk_ms: 5000, generation: 1, sealed: false, evidence: { hostname: 'www.svt.se' } as TrafficChunk['evidence'], samples, ...extra,
}) as TrafficChunk

it('merges 50 ms samples per series into 250 ms ticks, newest first, inside the range only', () => {
  const lines = feedLines([chunk('a', 10_000, [[0, 10, 100, 0, 0, 1, 1], [100, 5, 0, 0, 0, 1, 0], [300, 0, 0, 0, 0, 0, 0], [500, 1, 2, 0, 0, 1, 1], [5_000, 9, 9, 0, 0, 1, 1]])], 10_000, 11_000)
  expect(lines.map(line => [line.atMs, line.sent, line.received])).toEqual([[10_500, 1, 2], [10_000, 15, 100]])
  expect(lines[0]).toMatchObject({ clientIp: '10.0.0.2', service: 'svt.se', host: 'www.svt.se', endpoint: '1.2.3.4:443', protocol: 'tcp' })
})

it('skips hidden clients', () => {
  const chunks = [chunk('a', 0, [[0, 1, 1, 0, 0, 1, 1]]), chunk('b', 0, [[0, 1, 1, 0, 0, 1, 1]], { client_id: 'c2', client_ip: '10.0.0.3' })]
  expect(feedLines(chunks, 0, 1000, item => item.client_id === 'c2').map(line => line.clientIp)).toEqual(['10.0.0.2'])
})

it('lets late capture update a tick and keeps the newest lines within the limit', () => {
  const first = feedLines([chunk('a', 0, [[0, 1, 0, 0, 0, 1, 0]])], 0, 1000)
  const late = feedLines([chunk('a', 0, [[0, 1, 0, 0, 0, 1, 0], [50, 2, 0, 0, 0, 1, 0], [600, 0, 4, 0, 0, 0, 1]])], 0, 1000)
  const merged = mergeFeed(first, late, 10)
  expect(merged.map(line => [line.atMs, line.sent, line.received])).toEqual([[500, 0, 4], [0, 3, 0]])
  expect(mergeFeed(first, late, 1)).toHaveLength(1)
})

it('counts lines per second before the cursor', () => {
  const lines = [{ atMs: 9_250 }, { atMs: 9_500 }, { atMs: 8_000 }, { atMs: 1_000 }] as unknown as Parameters<typeof feedRate>[0]
  expect(feedRate(lines, 9_900, 3)).toEqual([0, 1, 2])
})
