import { describe, expect, it } from 'vitest'
import { chooseLOD } from '../transport/sessionController'
import { frameForTime, timeForFrame, windowSegments } from './time'

describe('shared canonical timeline projection', () => {
  it('maps epoch milliseconds to frames and back within half a frame', () => {
    const epoch = Date.parse('2026-09-02T10:00:00Z')
    const target = epoch + 123_456
    const frame = frameForTime(epoch, target, 30)
    expect(Math.abs(timeForFrame(epoch, frame, 30) - target)).toBeLessThanOrEqual(1000 / 60)
  })

  it('uses stable ten-second page boundaries', () => {
    expect(windowSegments(12_345, 31_000)).toEqual([
      { fromMs: 10_000, toMs: 20_000 },
      { fromMs: 20_000, toMs: 30_000 },
      { fromMs: 30_000, toMs: 40_000 },
    ])
  })

  it('selects activity resolution from the requested viewport span', () => {
    expect(chooseLOD(0, 60_000)).toBe('50ms')
    expect(chooseLOD(0, 300_000)).toBe('500ms')
    expect(chooseLOD(0, 300_001)).toBe('5s')
  })
})
