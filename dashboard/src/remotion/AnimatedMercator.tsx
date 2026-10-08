import { memo, useEffect, useRef } from 'react'
import DeckGL from '@deck.gl/react'
import type { DeckGLProps, DeckGLRef } from '@deck.gl/react'
import type { MapPlaybackClock } from '../map/mapPlaybackClock'

/** Only shader uniforms read the playback clock. No React/layer props at frame rate. */
export const AnimatedMercator = memo(function AnimatedMercator({ clock, active, ...props }: DeckGLProps & { clock: MapPlaybackClock; active: boolean }) {
  const deck = useRef<DeckGLRef>(null)
  useEffect(() => {
    let lastPaint = -Infinity
    const redraw = () => {
      // Fixed wall-clock slots avoid dropping every other paint when a slow
      // frame lands just before a sliding 33 ms deadline. Replay rate stays free.
      const slot = Math.floor(performance.now() * 30 / 1000)
      if (active && !document.hidden && slot !== lastPaint) {
        lastPaint = slot
        deck.current?.deck?.redraw('traffic clock')
      }
    }
    const seek = () => { lastPaint = -Infinity; redraw() }
    clock.addEventListener('animationframe', redraw)
    clock.addEventListener('seeked', seek)
    clock.addEventListener('pause', seek)
    clock.addEventListener('ended', seek)
    document.addEventListener('visibilitychange', redraw)
    return () => {
      clock.removeEventListener('animationframe', redraw)
      clock.removeEventListener('seeked', seek)
      clock.removeEventListener('pause', seek)
      clock.removeEventListener('ended', seek)
      document.removeEventListener('visibilitychange', redraw)
    }
  }, [active, clock])
  return <DeckGL ref={deck} {...props} />
})
