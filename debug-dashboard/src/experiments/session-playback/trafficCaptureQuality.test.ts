import { describe, expect, it } from 'vitest'
import type { Flow } from '@infrareveal/session-state'
import type { TimelineClip } from '../../model/sessionModel'
import { captureShortfalls } from './trafficCaptureQuality'

const flow = { id: 'svt', start: new Date(5000).toISOString(), last_seen: new Date(65000).toISOString(), bytes_in: 16_832_457, bytes_out: 471_155 } as Flow
const clip = { flowId: 'svt', activity: { wireBytesIn: 3722, wireBytesOut: 527685 } } as TimelineClip
const loaded = [{ fromMs: 0, toMs: 70000, flowIds: ['svt'] }]

describe('Traffic capture integrity', () => {
  it('flags the recorded large download whose packet detail omitted almost all incoming bytes', () => {
    expect(captureShortfalls([clip], new Map([['svt', flow]]), loaded).get('svt')).toEqual({ capturedBytes: 531407, totalBytes: 17303612 })
  })
  it('does not confuse an unloaded or partial viewport with capture loss', () => {
    for (const ranges of [[], [{ ...loaded[0], toMs: 30000 }], [{ ...loaded[0], flowIds: ['another'] }], [{ ...loaded[0], toMs: 30000 }, { ...loaded[0], fromMs: 35000 }]]) {
      expect(captureShortfalls([clip], new Map([['svt', flow]]), ranges).size).toBe(0)
    }
  })
  it('joins completed viewport and pinned evidence requests without bridging gaps', () => {
    expect(captureShortfalls([clip], new Map([['svt', flow]]), [{ ...loaded[0], toMs: 35000 }, { ...loaded[0], fromMs: 35000 }]).has('svt')).toBe(true)
  })
  it('compares wire counters, allowing header overhead and ordinary small differences', () => {
    for (const wireBytesIn of [flow.bytes_in + 120000, flow.bytes_in * .95]) {
      const healthy = { ...clip, activity: { ...clip.activity, wireBytesIn } }
      expect(captureShortfalls([healthy], new Map([['svt', flow]]), loaded).size).toBe(0)
    }
    const small = { ...flow, bytes_in: 2000, bytes_out: 100 }
    expect(captureShortfalls([clip], new Map([['svt', small]]), loaded).size).toBe(0)
  })
})
