import { memo, useEffect, useRef } from 'react'
import DeckGL from '@deck.gl/react'
import type { DeckGLProps, DeckGLRef } from '@deck.gl/react'
import type { View } from '@deck.gl/core'
import type { MapPlaybackClock } from '../map/mapPlaybackClock'

/** Only shader uniforms read the playback clock. No React/layer props at frame rate. Renders the flat map or the globe. */
export const AnimatedMercator = memo(function AnimatedMercator({ clock, active, ...props }: DeckGLProps<View> & { clock: MapPlaybackClock; active: boolean }) {
  const deck = useRef<DeckGLRef<View>>(null)
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
