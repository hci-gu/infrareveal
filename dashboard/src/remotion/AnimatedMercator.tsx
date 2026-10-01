import { memo, useMemo } from 'react'
import DeckGL from '@deck.gl/react'
import type { DeckGLProps } from '@deck.gl/react'
import { useCurrentFrame } from 'remotion'
import { timeForFrame } from '@infrareveal/session-state'
import { FlowArcLayer } from '../map/FlowArcLayer'
import { FlowPathLayer } from '../map/FlowPathLayer'
import { TRAFFIC_BUCKET_MS } from '../map/mapTraffic'

/** The video clock reaches only the shader uniforms, never the sidebar or geometry. */
export const AnimatedMercator = memo(function AnimatedMercator({ fps, playbackEpochMs, trafficAnchorMs, layers, ...props }: DeckGLProps & { fps: number; playbackEpochMs: number; trafficAnchorMs: number }) {
  const frame = useCurrentFrame()
  const animated = useMemo(() => layers?.flat().map(layer => layer instanceof FlowArcLayer || layer instanceof FlowPathLayer
    ? layer.clone({ time: frame / fps, phase: (timeForFrame(playbackEpochMs, frame, fps) - trafficAnchorMs) / TRAFFIC_BUCKET_MS }) : layer),
  [layers, frame, fps, playbackEpochMs, trafficAnchorMs])
  return <DeckGL {...props} layers={animated} />
})
