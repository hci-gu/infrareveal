import { useEffect } from 'react'
import { sessionTimelineStore, setTimelinePlayback, timelineStartMs } from '@infrareveal/session-state'
import { clampTime } from './trafficTime'

/** The active Traffic route drives playback; the shared controller owns server time. */
export function useTrafficPlayback(sessionId: string | null) {
  useEffect(() => {
    if (!sessionId) return
    let frame = 0
    let previous = performance.now()
    let published = previous
    const tick = (now: number) => {
      const delta = Math.max(0, Math.min(250, now - previous))
      previous = now
      const state = sessionTimelineStore.getState()
      const manifest = state.manifest
      if (manifest?.sessionId === sessionId && now - published >= 32) {
        const fromMs = timelineStartMs(state)
        const toMs = manifest.active ? state.liveEdgeMs : Date.parse(manifest.endedAt || manifest.coverage.to)
        if (Number.isFinite(fromMs) && Number.isFinite(toMs)) {
          if (state.playback === 'following') setTimelinePlayback({ cursorMs: toMs, ...(!manifest.active ? { playback: 'paused' as const } : {}) })
          if (state.playback === 'playing') {
            const cursorMs = clampTime(state.cursorMs + (now - published) * state.rate, { fromMs, toMs })
            setTimelinePlayback({ cursorMs, ...(cursorMs >= toMs ? { playback: 'paused' as const } : {}) })
          }
        }
        published = now
      } else if (delta >= 250) published = now
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [sessionId])
}
