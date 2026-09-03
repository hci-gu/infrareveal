import { describe, expect, it } from 'vitest'
import type { PipelineEvent } from '../types'
import { gapEvent, mergeLiveEvents } from './mergeLiveEvents'

describe('mergeLiveEvents', () => {
  it('uses measured timing while retaining durable labels and removes duplicates', () => {
    const durable = event('flow:record-1:discovered', 1000, 0, 'derived', { hostname: 'durable.example', flowKey: 'flow-key' })
    const live = event('flow-discovered:record-1', 900, 14, 'observed', { protocol: 'tcp', flowKey: 'flow-key' })
    const merged = mergeLiveEvents([durable], [live], 1100)
    expect(merged).toHaveLength(1)
    expect(merged[0]).toMatchObject({ occurredAtMs: 900, sequence: 14, timing: 'observed' })
    expect(merged[0].summary).toMatchObject({ protocol: 'tcp', hostname: 'durable.example' })
  })

  it('deduplicates sequence numbers and expires unmatched live events', () => {
    const sameSequence = [event('a', 99_000, 7), event('b', 99_100, 7)]
    const expired = event('expired', 1, 8)
    expect(mergeLiveEvents([], [...sameSequence, expired], 100_000).map((item) => item.id)).toEqual(['a'])
  })

  it('turns a gap into an explicit unknown capture event', () => {
    expect(gapEvent({
      type: 'gap', version: 1, sessionId: 'session', events: [], droppedEvents: 12,
      serverNowMs: 1000, requestedSequence: 2, oldestSequence: 15, newestSequence: 20,
      ingressRejected: 0, subscriberDropped: 0, burstDiscarded: 0,
    })).toMatchObject({ kind: 'health', summary: { droppedEvents: 12, captureComplete: false } })
  })
})

function event(
  id: string,
  occurredAtMs: number,
  sequence: number,
  timing: PipelineEvent['timing'] = 'observed',
  summary: PipelineEvent['summary'] = {},
): PipelineEvent {
  return {
    id, sequence, sessionId: 'session', traceId: 'trace', kind: 'flow', stage: 'conntrack',
    occurredAtMs, timing, summary,
  }
}
