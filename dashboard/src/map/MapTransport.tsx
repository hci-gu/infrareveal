import { useId } from 'react'
import type { CSSProperties } from 'react'
import { MapIcon } from './MapIcon'
import { formatCursor, formatMinute } from './format'
import { waveformCeiling } from './wireWaveform'
import type { WireBin } from './wireWaveform'
import type { MapTimelineScene } from './mapModel'
import { TimelineFlows } from './TimelineFlows'
import { timelineTicks } from './timelineTicks'

type Props = {
  scene: MapTimelineScene
  bins: WireBin[]
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

/** Keep tick labels clear of the end label ("Live" / end time). */
const END_LABEL_CLEARANCE = 0.08

export function MapTransport({ scene, bins, endMs, frame, fps, playing, rate, live, following, onToggle, onSeek, onStep, onRate, onLive }: Props) {
  const gradientId = useId()
  const peak = waveformCeiling([bins])
  const duration = Math.max(1, (endMs - scene.startMs) / 1000)
  const maxFrame = Math.max(1, Math.floor(duration * fps))
  const progress = Math.min(100, Math.max(0, frame / maxFrame * 100))
  const cursorMs = scene.startMs + frame / fps * 1000
  const { step, ticks } = timelineTicks(scene.startMs, endMs, 6)
  const label = (time: number) => step >= 60_000 ? formatMinute(time) : formatCursor(time)

  return <footer className="atlas-transport" aria-label="Session playback" style={{ '--progress': `${progress}%` } as CSSProperties}>
    <span className="atlas-transport-title"><MapIcon name="activity" size={14} />Session timeline</span>
    <div className="atlas-transport-meta">
      <span className="atlas-transport-cursor" aria-live="off">{formatCursor(cursorMs)}{live && following ? <small>live</small> : null}</span>
      <span className="atlas-transport-legend"><span className="atlas-down">↓ Downloaded</span><span className="atlas-up">↑ Sent</span></span>
    </div>
    <span className="atlas-key-hint"><kbd>space</kbd> play / pause</span>

    <div className="atlas-playback-buttons">
      <button type="button" className="atlas-icon-button atlas-skip" onClick={() => onStep(-fps * 10)} aria-label="Back 10 seconds" title="Back 10 seconds"><MapIcon name="rewind" size={18} /></button>
      <button type="button" className="atlas-play-button" onClick={onToggle} aria-label={playing ? 'Pause playback' : 'Play session'} title={playing ? 'Pause (Space)' : 'Play (Space)'}><MapIcon name={playing ? 'pause' : 'play'} size={18} /></button>
      <button type="button" className="atlas-icon-button atlas-skip" onClick={() => onStep(fps * 10)} aria-label="Forward 10 seconds" title="Forward 10 seconds"><MapIcon name="forward" size={18} /></button>
    </div>

    <div className="atlas-timeline-track">
      <svg className="atlas-flow-definitions" aria-hidden="true"><defs>
        {(['received', 'sent'] as const).map(direction => <linearGradient key={direction} id={`${gradientId}-${direction}`} x1="0" y1={direction === 'received' ? '1' : '0'} x2="0" y2={direction === 'received' ? '0' : '1'} className={`atlas-flow-${direction}`}><stop offset="0" stopColor="currentColor" stopOpacity=".95" /><stop offset="1" stopColor="currentColor" stopOpacity=".35" /></linearGradient>)}
      </defs></svg>
      <div className="atlas-timeline-grid" aria-hidden="true">{ticks.map(tick => <i key={tick.time} style={{ left: `${tick.fraction * 100}%` }} />)}</div>
      {/* The bar spans the whole retained session but only the window around the
          playhead is loaded, so unobserved bins are not shown as capture gaps. */}
      <TimelineFlows bins={bins} ceiling={peak} gradientId={gradientId} available gaps={false} />
      <div className="atlas-timeline-future" aria-hidden="true" />
      <div className="atlas-timeline-playhead" aria-hidden="true"><span /></div>
      <input type="range" aria-label="Session timeline" aria-valuetext={`${formatCursor(cursorMs)} of ${formatCursor(endMs)}`} min={0} max={maxFrame} step={1} value={Math.min(frame, maxFrame)} onChange={(event) => onSeek(Number(event.target.value))} />
    </div>

    <div className="atlas-transport-actions">
      <label className="atlas-speed"><span className="atlas-sr-only">Playback speed</span><select value={rate} onChange={(event) => onRate(Number(event.target.value))}>{[0.5, 1, 2, 4].map((speed) => <option key={speed} value={speed}>{speed}×</option>)}</select></label>
      {live ? <button type="button" className={`atlas-live-button ${following ? 'is-following' : ''}`} onClick={onLive}><i className="atlas-dot" />{following ? 'Live' : 'Go live'}</button> : <span className="atlas-recorded-label">Recorded</span>}
    </div>

    <div className="atlas-timeline-axis" aria-hidden="true">
      {ticks.filter(tick => tick.fraction < 1 - END_LABEL_CLEARANCE).map(tick => <span key={tick.time} style={{ left: `${tick.fraction * 100}%` }}>{label(tick.time)}</span>)}
      <span className="is-end">{live ? 'Live edge' : formatCursor(endMs)}</span>
    </div>
  </footer>
}
