import { describe, expect, it } from 'vitest'
import type { PipelineEvent } from '../types'
import { TemporalEventIndex } from './temporalEventIndex'

describe('TemporalEventIndex', () => {
  it('queries indexed time/facets and finds the nearest trace event', () => {
    const index = new TemporalEventIndex(50)
    index.upsert(event('later', 130, 'flow-b', '10.0.0.2', 'remote_to_client'))
    index.upsert(event('first', 100, 'flow-a', '10.0.0.1', 'client_to_remote'))
    index.upsert(event('middle', 120, 'flow-a', '10.0.0.1', 'client_to_remote'))

    expect(index.query(90, 125, { clients: ['10.0.0.1'], directions: ['client_to_remote'] }).map((item) => item.id))
      .toEqual(['first', 'middle'])
    expect(index.nearestBefore(125, 'flow-a')?.id).toBe('middle')
    expect(index.query(1000, 2000)).toEqual([])
  })

  it('synchronizes incremental revisions without retaining evicted detail', () => {
    const index = new TemporalEventIndex()
    index.synchronize([event('a', 100, 'one'), event('b', 200, 'two')])
    index.synchronize([{ ...event('b', 250, 'two'), summary: { clientIp: 'changed' } }])
    expect(index.size).toBe(1)
    expect(index.query(0, 1000).map((item) => [item.id, item.occurredAtMs])).toEqual([['b', 250]])
  })

  it('narrows a 60-minute synthetic session to a 30-second bucket window', () => {
    const index = new TemporalEventIndex(1000)
    for (let second = 0; second < 60 * 60; second += 1) {
      for (let item = 0; item < 10; item += 1) {
        index.upsert(event(`${second}:${item}`, second * 1000 + item, `trace-${item}`, `10.0.0.${2 + (second + item) % 30}`))
      }
    }
    const started = performance.now()
    const result = index.query(30 * 60 * 1000, (30 * 60 + 30) * 1000)
    expect(result).toHaveLength(300)
    expect(index.size).toBe(36_000)
    expect(performance.now() - started).toBeLessThan(1000)
  })
})

function event(
  id: string,
  occurredAtMs: number,
  traceId: string,
  clientIp = '10.0.0.1',
  direction: PipelineEvent['direction'] = 'client_to_remote',
): PipelineEvent {
  return {
    id, sequence: 0, sessionId: 'session', traceId, kind: 'burst', stage: 'header_capture',
    direction, occurredAtMs, timing: 'observed', summary: { clientIp },
  }
}
