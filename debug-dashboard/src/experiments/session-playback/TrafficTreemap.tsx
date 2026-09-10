import { Player } from '@remotion/player'
import type { PlayerRef } from '@remotion/player'
import { useEffect, useMemo, useRef } from 'react'
import { frameForTime } from '@infrareveal/session-state'
import { SessionComposition } from '../../remotion/SessionComposition'
import type { SessionComposition as Composition } from '../../model/sessionModel'
import { selectSceneWindow } from '../../timeline/selectors/selectSceneWindow'
import type { TrafficSelection } from './trafficModel'

export function TrafficTreemap({ composition, cursorMs, onSelect }: { composition: Composition; cursorMs: number; onSelect: (selection: TrafficSelection) => void }) {
  const player = useRef<PlayerRef>(null)
  const sceneWindow = useMemo(() => selectSceneWindow(composition, { fromMs: composition.sessionStartMs, toMs: composition.sessionEndMs, overview: true, focusedServiceId: null, selectedClipId: null }), [composition])
  useEffect(() => { player.current?.seekTo(frameForTime(composition.sessionStartMs, cursorMs, composition.fps)) }, [composition.fps, composition.sessionStartMs, cursorMs])
  useEffect(() => {
    const select = (event: Event) => {
      const detail = (event as CustomEvent<{ kind: string; id: string }>).detail
      if (detail?.kind === 'clip') { const clip = composition.clips.find(c => c.id === detail.id); if (clip) onSelect({ kind: 'flow', id: clip.flowId, flowId: clip.flowId }) }
      if (detail?.kind === 'service') { const clip = composition.clips.find(c => c.serviceGroupId === detail.id); if (clip) onSelect({ kind: 'flow', id: clip.flowId, flowId: clip.flowId }) }
    }
    window.addEventListener('infrareveal:select', select)
    return () => window.removeEventListener('infrareveal:select', select)
  }, [composition.clips, onSelect])
  return <div className="traffic-treemap" aria-label="Secondary treemap view"><Player ref={player} component={SessionComposition} inputProps={{ sceneWindow, viewMode: 'treemap', zoomFrames: 'all', selectedClipId: null, selectedServiceId: null, focusedServiceId: null, collapsedServiceIds: [], followLive: false }} compositionWidth={composition.width} compositionHeight={composition.height} durationInFrames={composition.durationInFrames} fps={composition.fps} controls={false} clickToPlay={false} doubleClickToFullscreen={false} style={{ width: '100%', height: '100%' }} /></div>
}
