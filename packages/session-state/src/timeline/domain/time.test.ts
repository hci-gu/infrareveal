import { describe, expect, it } from 'vitest'
import { frameForTime, timeForFrame } from './time'

describe('shared canonical timeline projection', () => {
  it('maps epoch milliseconds to frames and back within half a frame', () => {
    const epoch = Date.parse('2026-09-02T10:00:00Z')
    const target = epoch + 123_456
    const frame = frameForTime(epoch, target, 30)
    expect(Math.abs(timeForFrame(epoch, frame, 30) - target)).toBeLessThanOrEqual(1000 / 60)
  })
})
