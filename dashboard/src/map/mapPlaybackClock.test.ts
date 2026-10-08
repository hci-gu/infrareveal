import { describe, expect, it } from 'vitest'
import { MapPlaybackClock, trafficAnimationTime } from './mapPlaybackClock'

function harness() {
  let now = 0
  let pending: FrameRequestCallback | undefined
  const clock = new MapPlaybackClock(30, { now: () => now, request: cb => { pending = cb; return 1 }, cancel: () => { pending = undefined } })
  clock.configure({ durationInFrames: 30_000, rate: 1 })
  return { clock, advance(ms: number) { now += ms; const cb = pending; pending = undefined; cb?.(now) }, queued: () => Boolean(pending) }
}

describe('map playback independent of React frames', () => {
  it('paints between timeline frames at slow replay rates without republishing React time', () => {
    const h = harness(); let paints = 0; let publications = 0
    h.clock.configure({ durationInFrames: 300, rate: .5 })
    h.clock.addEventListener('animationframe', () => { paints++ })
    h.clock.addEventListener('frameupdate', () => { publications++ })
    h.clock.play(); h.advance(16); h.advance(16)
    expect(paints).toBe(2)
    expect(publications).toBe(0)
    expect(h.clock.getTimeSeconds()).toBeCloseTo(.016)
    expect(trafficAnimationTime({ clock: h.clock, epochMs: 1000, anchorMs: 1000 }, 0, 0, 500)).toEqual({ time: .016, phase: .032 })
    h.clock.pause(); h.advance(1000)
    expect(paints).toBe(2)
    expect(h.clock.getTimeSeconds()).toBeCloseTo(.016)
  })
  it('keeps real elapsed time across dropped display frames and a long frame origin', () => {
    const h = harness()
    h.clock.configure({ durationInFrames: 30 * 100_000, rate: 1 })
    h.clock.seekTo(30 * 86_400)
    h.clock.play()
    h.advance(230)
    expect(h.clock.getCurrentFrame()).toBe(30 * 86_400 + 6)
    h.advance(770)
    expect(h.clock.getCurrentFrame()).toBe(30 * 86_400 + 30)
  })
  it('pauses exactly, seeks while paused, and changes rate without losing elapsed time', () => {
    const h = harness()
    h.clock.play(); h.advance(1100); h.clock.pause()
    const frame = h.clock.getCurrentFrame()
    h.advance(2000)
    expect(h.clock.getCurrentFrame()).toBe(frame)
    expect(h.queued()).toBe(false)
    h.clock.seekTo(600)
    expect(h.clock.getCurrentFrame()).toBe(600)
    h.clock.play(); h.advance(1000)
    h.clock.configure({ durationInFrames: 30_000, rate: 2 }); h.advance(1000)
    expect(h.clock.getCurrentFrame()).toBe(690)
  })
  it('extending a live duration does not restart playback; recorded end fires once', () => {
    const h = harness(); let ends = 0
    h.clock.addEventListener('ended', () => { ends++ })
    h.clock.configure({ durationInFrames: 60, rate: 1 }); h.clock.play(); h.advance(1000)
    h.clock.configure({ durationInFrames: 90, rate: 1 }); h.advance(1000)
    expect(h.clock.getCurrentFrame()).toBe(60)
    h.advance(1000); h.advance(1000)
    expect(h.clock.getCurrentFrame()).toBe(89)
    expect(h.clock.isPlaying()).toBe(false)
    expect(ends).toBe(1)
    expect(h.queued()).toBe(false)
  })
  it('publishes discrete frames only, and releases scheduled work on teardown', () => {
    const h = harness(); const frames: number[] = []
    h.clock.addEventListener('frameupdate', e => frames.push(e.detail.frame))
    h.clock.play(); h.advance(5); h.advance(5); h.advance(24)
    expect(frames).toEqual([1])
    h.clock.dispose()
    expect(h.queued()).toBe(false)
  })
})
