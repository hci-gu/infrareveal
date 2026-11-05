import type { CSSProperties } from 'react'
import { MapIcon } from './MapIcon'
import { formatCursor } from './format'
import { waveformCeiling } from './wireWaveform'
import type { WireBin } from './wireWaveform'
import type { TrafficDirection } from './mapWorkspace'
import type { MapTimelineScene } from './mapModel'

type Props = {
  scene: MapTimelineScene
  bins: WireBin[]
  direction: TrafficDirection
  endMs: number
  frame: number
  fps: number
  playing: boolean
  rate: number
  live: boolean
  following: boolean
  onToggle: () => void
  onSeek: (frame: number) => void
  onStep: (frames: number) => void
  onRate: (rate: number) => void
  onLive: () => void
}

export function MapTransport({ scene, bins, direction, endMs, frame, fps, playing, rate, live, following, onToggle, onSeek, onStep, onRate, onLive }: Props) {
  const peak = waveformCeiling([bins], direction)
  const duration = Math.max(1, (endMs - scene.startMs) / 1000)
  const maxFrame = Math.max(1, Math.floor(duration * fps))
  const progress = Math.min(100, Math.max(0, frame / maxFrame * 100))

  return <footer className="atlas-transport" aria-label="Session playback">
    <div className="atlas-transport-heading"><span><MapIcon name="activity" size={14} />SESSION TIMELINE</span><span className="atlas-timeline-description">Captured wire rate · selection</span><span className="atlas-key-hint"><kbd>space</kbd> to play / pause</span></div>
    <div className="atlas-transport-body">
      <div className="atlas-playback-buttons">
        <button type="button" className="atlas-icon-button atlas-skip" onClick={() => onStep(-fps * 10)} aria-label="Back 10 seconds" title="Back 10 seconds"><MapIcon name="rewind" size={19} /></button>
        <button type="button" className="atlas-play-button" onClick={onToggle} aria-label={playing ? 'Pause playback' : 'Play session'} title={playing ? 'Pause (Space)' : 'Play (Space)'}><MapIcon name={playing ? 'pause' : 'play'} size={20} /></button>
        <button type="button" className="atlas-icon-button atlas-skip" onClick={() => onStep(fps * 10)} aria-label="Forward 10 seconds" title="Forward 10 seconds"><MapIcon name="forward" size={19} /></button>
      </div>
      <div className="atlas-timeline">
        <div className="atlas-timeline-track" style={{ '--progress': `${progress}%` } as CSSProperties}>
          <div className="atlas-timeline-bars atlas-directional-bars" aria-hidden="true">{bins.map((bin, index) => <i key={index} className={bin.complete ? "" : "is-partial"}>{bin.observed && <>{direction !== "sent" && <b className="received" style={{ height: `${bin.received / peak * 50}%` }} />}{direction !== "received" && <b className="sent" style={{ height: `${bin.sent / peak * 50}%` }} />}</>}</i>)}</div>
          <div className="atlas-timeline-playhead" aria-hidden="true"><span /></div>
          <input type="range" aria-label="Session timeline" aria-valuetext={`${formatCursor(scene.startMs + frame / fps * 1000)} of ${formatCursor(endMs)}`} min={0} max={maxFrame} step={1} value={Math.min(frame, maxFrame)} onChange={(event) => onSeek(Number(event.target.value))} />
        </div>
        <div className="atlas-timeline-labels">{[0, 1, 2, 3].map(tick => <span key={tick}>{formatCursor(scene.startMs + duration * 1000 * tick / 4)}</span>)}<span>{live ? 'LIVE EDGE' : formatCursor(endMs)}</span></div>
      </div>
      <div className="atlas-transport-actions"><label className="atlas-speed"><span className="atlas-sr-only">Playback speed</span><select value={rate} onChange={(event) => onRate(Number(event.target.value))}>{[0.5, 1, 2, 4].map((speed) => <option key={speed} value={speed}>{speed}×</option>)}</select></label>{live ? <button type="button" className={`atlas-live-button ${following ? 'is-following' : ''}`} onClick={onLive}><i className="atlas-dot" />{following ? 'Live' : 'Go live'}</button> : <span className="atlas-recorded-label">RECORDED</span>}</div>
    </div>
  </footer>
}
