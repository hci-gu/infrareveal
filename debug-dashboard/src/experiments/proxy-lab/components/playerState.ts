import { frameForTime, timeForFrame } from '@infrareveal/session-state'

export type PlayerTransition = {
  frame: number
  cursorMs: number
  playback: 'following' | 'playing' | 'paused'
}

export function playTransition(frame: number, epochMs: number, fps: number, following: boolean): PlayerTransition {
  return { frame, cursorMs: timeForFrame(epochMs, frame, fps), playback: following ? 'following' : 'playing' }
}

export function pauseTransition(frame: number, epochMs: number, fps: number): PlayerTransition {
  return { frame, cursorMs: timeForFrame(epochMs, frame, fps), playback: 'paused' }
}

export function seekTransition(frame: number, durationInFrames: number, epochMs: number, fps: number): PlayerTransition {
  const next = Math.max(0, Math.min(durationInFrames - 1, Math.round(frame)))
  return pauseTransition(next, epochMs, fps)
}

export function goLiveTransition(liveEdgeMs: number, durationInFrames: number, epochMs: number, fps: number): PlayerTransition {
  const frame = Math.max(0, Math.min(durationInFrames - 1, frameForTime(epochMs, liveEdgeMs - 500, fps)))
  return { frame, cursorMs: timeForFrame(epochMs, frame, fps), playback: 'following' }
}

export function neighboringEventFrame(
  eventTimes: readonly number[],
  cursorMs: number,
  direction: 'previous' | 'next',
  epochMs: number,
  fps: number,
) {
  const ordered = Array.from(new Set(eventTimes)).sort((left, right) => left - right)
  const target = direction === 'previous'
    ? ordered.filter((time) => time < cursorMs - 1).pop()
    : ordered.find((time) => time > cursorMs + 1)
  return target === undefined ? null : frameForTime(epochMs, target, fps)
}
