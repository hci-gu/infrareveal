import { memo, useEffect, useRef } from 'react'
import DeckGL from '@deck.gl/react'
import type { DeckGLProps, DeckGLRef } from '@deck.gl/react'
import type { MapPlaybackClock } from '../map/mapPlaybackClock'

/** Only shader uniforms read the playback clock. No React/layer props at frame rate. */
export const AnimatedMercator = memo(function AnimatedMercator({ clock, active, ...props }: DeckGLProps & { clock: MapPlaybackClock; active: boolean }) {
  const deck = useRef<DeckGLRef>(null)
  useEffect(() => {
    const redraw = () => {
      if (active && !document.hidden) deck.current?.deck?.redraw('traffic clock')
    }
    clock.addEventListener('animationframe', redraw)
    clock.addEventListener('seeked', redraw)
    clock.addEventListener('pause', redraw)
    clock.addEventListener('ended', redraw)
    document.addEventListener('visibilitychange', redraw)
    return () => {
      clock.removeEventListener('animationframe', redraw)
      clock.removeEventListener('seeked', redraw)
      clock.removeEventListener('pause', redraw)
      clock.removeEventListener('ended', redraw)
      document.removeEventListener('visibilitychange', redraw)
    }
  }, [active, clock])
  return <DeckGL ref={deck} {...props} />
})
