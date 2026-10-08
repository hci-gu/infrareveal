import { describe, expect, it } from 'vitest'
import type { PipelineEvent } from '../types'
import { gapEvent, mergeLiveEvents } from './mergeLiveEvents'
import gateFixture from '../../../../../testdata/gate-event-contract-v1.json'
import { emptyGatewayData } from '@infrareveal/session-state'
import type { GateEvent } from '@infrareveal/session-state'
import { projectRecordedEvents } from './projectRecordedEvents'
import { decodePipelineStreamEnvelope } from '../data/traceClient'

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

  it.each(['live', 'legacyLive'] as const)('keeps queued and verdict phases distinct and reconciles %s with durable audit', source => {
    const live = decodePipelineStreamEnvelope({
      version: 1, sessionId: gateFixture.record.session, events: gateFixture[source],
      droppedEvents: 0, oldestSequence: 41, newestSequence: 42, serverNowMs: gateFixture.live[1].occurredAtMs,
    }).events
    const durable = projectRecordedEvents(emptyGatewayData(), [gateFixture.record as GateEvent], {
      fromMs: live[0].occurredAtMs - 1, toMs: live[1].occurredAtMs + 1,
    })
    expect(durable.map(item => item.id)).toEqual(gateFixture.expectedIDs)
    expect(live[0].stage).toBe(live[1].stage)
    expect(Math.floor(live[0].occurredAtMs / 50)).toBe(Math.floor(live[1].occurredAtMs / 50))
    const liveOnly = mergeLiveEvents([], live, live[1].occurredAtMs)
    expect(liveOnly.map(item => item.id)).toEqual(gateFixture.expectedIDs)
    expect(liveOnly[1]).toMatchObject({ parentId: gateFixture.expectedIDs[0], summary: { verdict: 'drop' } })
    const merged = mergeLiveEvents(durable, live, live[1].occurredAtMs)
    expect(merged).toEqual(durable)
    expect(merged[1]).toMatchObject({ parentId: gateFixture.expectedIDs[0], summary: { verdict: 'rejected' } })
  })

  it('keeps different decisions and bypassed packets on the same flow and bucket distinct', () => {
    const first = gateFixture.live[0] as PipelineEvent
    const events: PipelineEvent[] = [first,
      { ...first, id: 'gate:other-decision:queued', sequence: 43 },
      { ...first, id: 'gate-bypass:packet-one', sequence: 44 },
      { ...first, id: 'gate-bypass:packet-two', sequence: 45 },
    ]
    expect(mergeLiveEvents([], events, first.occurredAtMs)).toHaveLength(4)
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
