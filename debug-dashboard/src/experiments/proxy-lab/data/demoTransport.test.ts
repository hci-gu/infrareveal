import { describe, expect, it } from 'vitest'
import { demoPipelineEnvelope, isProxyLabDemoEnabled } from './demoTransport'

describe('proxy lab demo transport', () => {
  it('uses stable ordered IDs and covers every teaching category', () => {
    expect(demoPipelineEnvelope.events.map((event) => event.sequence)).toEqual(
      [...demoPipelineEnvelope.events].map((_, index) => index + 1),
    )
    expect(new Set(demoPipelineEnvelope.events.map((event) => event.kind))).toEqual(
      new Set(['dns', 'flow', 'burst', 'attribution', 'destination', 'route', 'gate', 'health']),
    )
    expect(demoPipelineEnvelope.events.some((event) => event.summary.protocol === 'udp')).toBe(true)
    expect(demoPipelineEnvelope.events.some((event) => event.summary.verdict === 'approved')).toBe(true)
    expect(demoPipelineEnvelope.events.some((event) => event.summary.verdict === 'rejected')).toBe(true)
    expect(demoPipelineEnvelope.droppedEvents).toBe(0)
    expect(demoPipelineEnvelope.events.find((event) => event.kind === 'health')?.summary.droppedEvents).toBe(37)
  })

  it('never enables the query switch in production', () => {
    expect(isProxyLabDemoEnabled('?demo=1', false, undefined)).toBe(false)
    expect(isProxyLabDemoEnabled('?demo=1', true, undefined)).toBe(true)
    expect(isProxyLabDemoEnabled('', false, 'true')).toBe(true)
  })
})
