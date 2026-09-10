import { useEffect } from 'react'
import { sessionTimelineStore, setTimelinePlayback } from '@infrareveal/session-state'

export function useLabPlayback({ sessionId, epochMs, endMs, active, demo }: { sessionId: string; epochMs: number; endMs: number; active: boolean; demo: boolean }) {
  useEffect(() => {
    let frame = 0, previous = performance.now()
    const tick = (now: number) => {
      const elapsed = now - previous
      if (elapsed >= 32) {
        previous = now
        const state = sessionTimelineStore.getState()
        if (demo || state.selectedSessionId === sessionId) {
          if (state.playback === 'following') setTimelinePlayback({ cursorMs: Math.max(epochMs, endMs - (active ? 500 : 0)), ...(!active ? { playback: 'paused' as const } : {}) })
          else if (state.playback === 'playing') {
            const cursorMs = Math.min(endMs, Math.max(epochMs, state.cursorMs + Math.min(elapsed, 250) * state.rate))
            setTimelinePlayback({ cursorMs, ...(cursorMs >= endMs ? { playback: 'paused' as const } : {}) })
          }
        }
      }
      frame = requestAnimationFrame(tick)
    }
    frame = requestAnimationFrame(tick)
    return () => cancelAnimationFrame(frame)
  }, [active, demo, endMs, epochMs, sessionId])
}
