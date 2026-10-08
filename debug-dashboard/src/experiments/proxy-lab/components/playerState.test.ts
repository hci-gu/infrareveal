import { describe, expect, it } from 'vitest'
import { goLiveTransition, neighboringEventFrame, pauseTransition, seekTransition } from './playerState'

describe('Lab replay transitions', () => {
  it('covers pause, seek, frame stepping, and go-live', () => {
    expect(pauseTransition(30, 1000, 30)).toMatchObject({ playback: 'paused', cursorMs: 2000 })
    expect(seekTransition(11.2, 100, 1000, 30)).toMatchObject({ frame: 11, playback: 'paused' })
    expect(seekTransition(12, 100, 1000, 30).frame - seekTransition(11, 100, 1000, 30).frame).toBe(1)
    expect(goLiveTransition(10_000, 300, 1000, 30)).toMatchObject({ playback: 'following', cursorMs: 9500 })
  })

  it('selects strict previous/next event frames', () => {
    expect(neighboringEventFrame([1000, 2000, 3000], 2000, 'previous', 1000, 30)).toBe(0)
    expect(neighboringEventFrame([1000, 2000, 3000], 2000, 'next', 1000, 30)).toBe(60)
  })
})
