import { AbsoluteFill, useCurrentFrame } from 'remotion'
import { timeForFrame } from '@infrareveal/session-state'
import type { PipelineEvent, ProxyLabMode } from '../types'
import { projectProxyScene } from '../model/projectProxyScene'
import { PipelineGraph } from './PipelineGraph'
import { PipelineHUD } from './PipelineHUD'
import { PipelineLegend } from './PipelineLegend'

export type ProxyLabCompositionProps = {
  epochMs: number
  fps: number
  events: PipelineEvent[]
  mode: ProxyLabMode
  selectedEventId: string | null
  selectedTraceId: string | null
}

/** Pure, seek-safe Remotion scene. All I/O and controls live in the page. */
export function ProxyLabComposition(props: ProxyLabCompositionProps) {
  const frame = useCurrentFrame()
  const cursorMs = timeForFrame(props.epochMs, frame, props.fps)
  const selected = props.events.find((event) => event.id === props.selectedEventId || event.traceId === props.selectedTraceId) ?? null
  const scene = projectProxyScene(props.events, cursorMs, { selectedId: props.selectedTraceId })
  return (
    <AbsoluteFill style={{ background: '#020617', fontFamily: 'Inter, sans-serif' }}>
      <PipelineGraph mode={props.mode} scene={scene} />
      <div style={{ bottom: 28, left: 34, position: 'absolute' }}><PipelineLegend /></div>
      <PipelineHUD cursorMs={cursorMs} mode={props.mode} scene={scene} selected={selected} />
    </AbsoluteFill>
  )
}
