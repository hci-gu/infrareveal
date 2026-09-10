import { Pause, Play } from 'lucide-react'
import { formatClock, formatDateTime } from '../../views/formatters'
import type { CoverageRange } from '../../shared/activity/captureCoverage'
import type { TimeRange } from './trafficTime'

export function TrafficTransport({ bounds, range, cursorMs, playing, following, live, rate, span, coverage, onSeek, onPlay, onLive, onRate, onSpan }: {
  bounds: TimeRange; range: TimeRange; cursorMs: number; playing: boolean; following: boolean; live: boolean; rate: number; span: number; coverage: CoverageRange[];
  onSeek: (time: number) => void; onPlay: () => void; onLive: () => void; onRate: (value: number) => void; onSpan: (value: number) => void
}) {
  const length = Math.max(1, bounds.toMs - bounds.fromMs)
  const percent = (time: number) => (time - bounds.fromMs) / length * 100
  return <div className="traffic-transport" aria-label="Playback and session navigator">
    <div className="traffic-play-controls"><button type="button" title="Back five seconds" aria-label="Back five seconds" onClick={() => onSeek(cursorMs - 5000)}>−5s</button><button type="button" className="traffic-play" title="Play / pause · Space" aria-label={playing ? 'Pause traffic' : 'Play traffic'} onClick={onPlay}>{playing ? <Pause size={17} /> : <Play size={17} />}</button><button type="button" title="Forward five seconds" aria-label="Forward five seconds" onClick={() => onSeek(cursorMs + 5000)}>+5s</button><div className="traffic-clock"><output title={formatDateTime(cursorMs)}>{formatClock(cursorMs)}</output><span>Playback position</span></div></div>
    <div className="traffic-session-navigator"><div className="scrubber-heading"><label htmlFor="traffic-scrubber">Drag to scrub through the session</label><span>{following ? 'At live edge' : playing ? 'Playing history' : 'View paused'}</span></div>
      <div className="traffic-scrub-rail"><div className="navigator-coverage" aria-hidden="true">{coverage.map(c => <i key={c.fromMs} className={c.level} style={{ left: `${percent(c.fromMs)}%`, width: `${percent(c.toMs) - percent(c.fromMs)}%` }} />)}<div className="navigator-window" style={{ left: `${percent(range.fromMs)}%`, width: `${(range.toMs - range.fromMs) / length * 100}%` }} /></div><input id="traffic-scrubber" type="range" min={bounds.fromMs} max={Math.max(bounds.fromMs, bounds.toMs)} step="1000" value={Math.max(bounds.fromMs, Math.min(bounds.toMs, cursorMs))} aria-label="Playback position; drag left to go back or right to go forward" aria-valuetext={formatDateTime(cursorMs)} onChange={event => onSeek(Number(event.target.value))} /></div>
      <div className="scrubber-bounds"><span>{formatClock(bounds.fromMs)}</span><span title="The rail shows loaded capture coverage; unreported regions are unknown">Capture coverage · outlined visible window</span><span>{formatClock(bounds.toMs)}</span></div>
    </div>
    <div className="traffic-play-options"><button type="button" className="traffic-follow" onClick={onLive}>{live ? following ? 'Following live' : 'Go live' : 'End'}</button><div><label>Speed<select aria-label="Traffic playback speed" value={rate} onChange={event => onRate(Number(event.target.value))}>{[.5, 1, 2].map(value => <option key={value} value={value}>{value}×</option>)}</select></label><label>Window<select aria-label="Traffic visible window" value={span} onChange={event => onSpan(Number(event.target.value))}>{[[10_000, '10s'], [30_000, '30s'], [60_000, '1m'], [300_000, '5m'], [0, 'All']].map(([value, label]) => <option key={value} value={value}>{label}</option>)}</select></label></div></div>
  </div>
}
