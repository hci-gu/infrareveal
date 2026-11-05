import { useCallback, useLayoutEffect, useRef } from 'react'
import type { MapPlaybackClock, PlaybackEventName } from './mapPlaybackClock'
import type { WireRange } from './wireWaveform'

export function timelineRange(startMs: number, endMs: number, cursorMs: number, windowMs: number, anchor: number | null, live: boolean): WireRange {
  // A growing live session follows playback time, not the server's stepped
  // manifest edge. A held window also keeps its span while new data arrives.
  const edge = Math.max(startMs + 1, anchor ?? (live ? cursorMs : endMs))
  const span = windowMs ? Math.min(windowMs, edge - startMs) : edge - startMs
  const to = Math.min(edge, Math.max(startMs + span, anchor ?? (windowMs ? cursorMs : edge)))
  return { from: Math.max(startMs, to - span), to }
}

/** Paint an affine viewport over prepared SVGs. The shared playback clock owns
 * motion; React/data publications only replace measured geometry and controls. */
export function useTimelineViewport({ clock, epochMs, cursorMs, startMs, endMs, windowMs, anchor, live, grid }: {
  clock?: MapPlaybackClock; epochMs: number; cursorMs: number; startMs: number; endMs: number
  windowMs: number; anchor: number | null; live: boolean; grid: WireRange
}) {
  const ref = useRef<HTMLElement>(null)
  const attach = useCallback((element: HTMLElement | null) => { ref.current = element }, [])
  const currentRange = () => timelineRange(startMs, endMs, clock ? epochMs + clock.getTimeSeconds() * 1000 : cursorMs, windowMs, anchor, live)
  useLayoutEffect(() => {
    const element = ref.current
    if (!element) return
    const paint = () => {
      const cursor = clock ? epochMs + clock.getTimeSeconds() * 1000 : cursorMs
      const range = timelineRange(startMs, endMs, cursor, windowMs, anchor, live)
      const span = Math.max(1, range.to - range.from)
      element.style.setProperty('--timeline-offset', `${(grid.from - range.from) / span * 100}%`)
      element.style.setProperty('--timeline-scale', String((grid.to - grid.from) / span))
      element.style.setProperty('--playhead', `${Math.max(0, Math.min(100, (cursor - range.from) / span * 100))}%`)
    }
    paint()
    const events: PlaybackEventName[] = ['animationframe', 'seeked', 'play', 'pause', 'ratechange', 'ended']
    for (const event of events) clock?.addEventListener(event, paint)
    return () => { for (const event of events) clock?.removeEventListener(event, paint) }
  }, [clock, epochMs, cursorMs, startMs, endMs, windowMs, anchor, live, grid.from, grid.to])
  return { ref: attach, currentRange }
}
