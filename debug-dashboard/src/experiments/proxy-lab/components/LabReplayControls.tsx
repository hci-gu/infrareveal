import { formatClock } from '../../../views/formatters'
import { FPS, frameForTime, setTimelinePlayback } from '@infrareveal/session-state'
import { goLiveTransition, neighboringEventFrame, seekTransition } from './playerState'
import type { PipelineEvent } from '../types'

export function LabReplayControls({ epochMs, endMs, cursorMs, playback, rate, active, events, onSeek }: { epochMs: number; endMs: number; cursorMs: number; playback: string; rate: number; active: boolean; events: PipelineEvent[]; onSeek: (time: number) => void }) {
  const count = Math.max(1, Math.ceil((endMs - epochMs) / 1000 * FPS) + 1)
  const frame = Math.min(count - 1, Math.max(0, frameForTime(epochMs, cursorMs, FPS)))
  const seek = (target: number) => onSeek(Math.min(endMs, seekTransition(target, count, epochMs, FPS).cursorMs))
  const event = (direction: 'previous' | 'next') => { const target = neighboringEventFrame(events.map(e => e.occurredAtMs), cursorMs, direction, epochMs, FPS); if (target !== null) seek(target) }
  const playing = playback === 'playing' || playback === 'following'
  return <details className="lab-replay"><summary>Replay &amp; event inspection <span>{formatClock(cursorMs)} · frame {frame} · {playing ? 'Playing' : 'Paused'}</span></summary><div className="lab-replay-controls">
    <button type="button" onClick={() => event('previous')}>Previous event</button><button type="button" aria-label="Lab back one frame" onClick={() => seek(frame - 1)}>− frame</button><button type="button" aria-label={playing ? 'Pause Lab replay' : 'Play Lab replay'} onClick={() => setTimelinePlayback({ playback: playing ? 'paused' : 'playing', ...(!playing && cursorMs >= endMs ? { cursorMs: epochMs } : {}) })}>{playing ? 'Pause' : 'Play'}</button><button type="button" aria-label="Lab forward one frame" onClick={() => seek(frame + 1)}>+ frame</button><button type="button" onClick={() => event('next')}>Next event</button>
    <label>Speed <select aria-label="Lab replay speed" value={rate} onChange={e => setTimelinePlayback({ rate: Number(e.target.value) })}>{[.05,.1,.25,.5,1,2,4].map(value => <option key={value} value={value}>{value}×</option>)}</select></label>
    {active ? <button type="button" onClick={() => { const next = goLiveTransition(endMs, count, epochMs, FPS); setTimelinePlayback({ playback: next.playback, cursorMs: next.cursorMs }) }}>Follow live</button> : null}
    <label className="lab-replay-range">Recording position <input aria-label="Lab replay position" type="range" min={0} max={count - 1} value={frame} onChange={e => seek(Number(e.target.value))} /></label>
    <p>Frame steps and reconstructed stage motion are explanatory timing. Source event timestamps retain their original precision.</p>
  </div></details>
}
