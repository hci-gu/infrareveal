import { describe, expect, it } from 'vitest'
import { timelineTicks } from './timelineTicks'

const at = (h: number, m: number, s = 0) => new Date(2026, 10, 17, h, m, s).getTime()

describe('timelineTicks', () => {
  it('uses round clock times for a 30 minute window', () => {
    const { step, ticks } = timelineTicks(at(12, 57, 11), at(13, 27, 14), 6)
    expect(step).toBe(10 * 60_000)
    expect(ticks.map(tick => new Date(tick.time).getMinutes())).toEqual([0, 10, 20])
    for (const tick of ticks) {
      expect(new Date(tick.time).getSeconds()).toBe(0)
      expect(tick.fraction).toBeGreaterThan(0)
      expect(tick.fraction).toBeLessThan(1)
    }
  })

  it('places ticks at their real position', () => {
    const { ticks } = timelineTicks(at(13, 0), at(13, 10), 6)
    expect(ticks[0]).toEqual({ time: at(13, 0), fraction: 0 })
    expect(ticks.find(tick => tick.time === at(13, 4))?.fraction).toBeCloseTo(0.4)
  })

  it('never exceeds the requested density', () => {
    for (const minutes of [1, 7, 45, 180, 900]) {
      expect(timelineTicks(at(9, 0), at(9, 0) + minutes * 60_000, 6).ticks.length).toBeLessThanOrEqual(7)
    }
  })

  it('handles an empty range', () => {
    expect(timelineTicks(1000, 1000).ticks).toEqual([])
  })
})
