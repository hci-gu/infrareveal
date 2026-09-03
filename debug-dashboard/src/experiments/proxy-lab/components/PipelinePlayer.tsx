import type { CallbackListener, PlayerRef } from '@remotion/player'
import { Player } from '@remotion/player'
import { ChevronFirst, ChevronLast, FastForward, Pause, Play, Radio, Rewind, StepBack, StepForward } from 'lucide-react'
import { useEffect, useRef, useState, type ReactNode } from 'react'
import { frameForTime, setTimelinePlayback, timeForFrame } from '@infrareveal/session-state'
import type { ActivityDataQuality as ActivityDataQualityModel, CaptureQualityInterval } from '../model/activityDataQuality'
import { PROXY_COMPOSITION_HEIGHT, PROXY_COMPOSITION_WIDTH } from '../model/graphLayout'
import { ProxyLabComposition, type ProxyLabCompositionProps } from '../remotion/ProxyLabComposition'
import { ActivityDataQuality } from './ActivityDataQuality'
import { goLiveTransition, neighboringEventFrame, pauseTransition, playTransition, seekTransition } from './playerState'

const rates = [0.05, 0.1, 0.25, 0.5, 1, 2, 4]

export function PipelinePlayer({ inputProps, durationInFrames, liveEdgeMs, playback, quality, rate, reduceMotion = false }: {
  inputProps: ProxyLabCompositionProps
  durationInFrames: number
  liveEdgeMs: number
  playback: 'following' | 'playing' | 'paused' | 'buffering'
  quality: ActivityDataQualityModel
  rate: number
  reduceMotion?: boolean
}) {
  const playerRef = useRef<PlayerRef>(null)
  const [currentFrame, setCurrentFrame] = useState(() => frameForTime(inputProps.epochMs, liveEdgeMs || inputProps.epochMs, inputProps.fps))
  const [isPlaying, setIsPlaying] = useState(false)
  const publishRef = useRef(0)
  const initializedEpochRef = useRef<number | null>(null)

  useEffect(() => {
    const player = playerRef.current
    if (!player) return
    if (initializedEpochRef.current === inputProps.epochMs) return
    initializedEpochRef.current = inputProps.epochMs
    const initial = Math.max(0, Math.min(durationInFrames - 1, frameForTime(inputProps.epochMs, liveEdgeMs || inputProps.epochMs, inputProps.fps)))
    player.seekTo(initial)
    setCurrentFrame(initial)
  }, [durationInFrames, inputProps.epochMs, inputProps.fps, liveEdgeMs])

  useEffect(() => {
    const player = playerRef.current
    if (!player) return
    const onFrame: CallbackListener<'frameupdate'> = (event) => {
      setCurrentFrame(event.detail.frame)
      const now = performance.now()
      if (now - publishRef.current < 100) return
      publishRef.current = now
      const cursorMs = timeForFrame(inputProps.epochMs, event.detail.frame, inputProps.fps)
      setTimelinePlayback({ cursorMs, viewport: { fromMs: cursorMs - 15_000, toMs: cursorMs + 15_000 } })
    }
    const onPlay = () => {
      setIsPlaying(true)
      const transition = playTransition(player.getCurrentFrame(), inputProps.epochMs, inputProps.fps, playback === 'following')
      setTimelinePlayback({ playback: transition.playback, cursorMs: transition.cursorMs })
    }
    const onPause = () => {
      setIsPlaying(false)
      const transition = pauseTransition(player.getCurrentFrame(), inputProps.epochMs, inputProps.fps)
      setTimelinePlayback({ playback: transition.playback, cursorMs: transition.cursorMs })
    }
    const onEnded = () => {
      setIsPlaying(false)
      setTimelinePlayback({ playback: 'paused' })
    }
    player.addEventListener('frameupdate', onFrame)
    player.addEventListener('play', onPlay)
    player.addEventListener('pause', onPause)
    player.addEventListener('ended', onEnded)
    return () => {
      player.removeEventListener('frameupdate', onFrame)
      player.removeEventListener('play', onPlay)
      player.removeEventListener('pause', onPause)
      player.removeEventListener('ended', onEnded)
    }
  }, [inputProps.epochMs, inputProps.fps, playback])

  useEffect(() => {
    const player = playerRef.current
    if (!player || playback !== 'following' || liveEdgeMs <= 0) return
    const transition = goLiveTransition(liveEdgeMs, durationInFrames, inputProps.epochMs, inputProps.fps)
    if (Math.abs(player.getCurrentFrame() - transition.frame) > inputProps.fps) player.seekTo(transition.frame)
    if (reduceMotion) player.pause()
    else if (!player.isPlaying()) player.play()
    setCurrentFrame(transition.frame)
    setTimelinePlayback({ playback: transition.playback, cursorMs: transition.cursorMs })
  }, [durationInFrames, inputProps.epochMs, inputProps.fps, liveEdgeMs, playback, reduceMotion])

  function applyTransition(transition: ReturnType<typeof seekTransition>, play = false) {
    const player = playerRef.current
    player?.seekTo(transition.frame)
    if (play) player?.play()
    else player?.pause()
    setCurrentFrame(transition.frame)
    setTimelinePlayback({
      cursorMs: transition.cursorMs,
      playback: transition.playback,
      viewport: { fromMs: transition.cursorMs - 15_000, toMs: transition.cursorMs + 15_000 },
    })
  }

  function seek(frame: number) {
    applyTransition(seekTransition(frame, durationInFrames, inputProps.epochMs, inputProps.fps))
  }

  function togglePlay() {
    const player = playerRef.current
    if (!player) return
    if (player.isPlaying()) player.pause()
    else player.play()
  }

  function seekEvent(direction: 'previous' | 'next') {
    const cursorMs = timeForFrame(inputProps.epochMs, currentFrame, inputProps.fps)
    const target = neighboringEventFrame(inputProps.events.map((event) => event.occurredAtMs), cursorMs, direction, inputProps.epochMs, inputProps.fps)
    if (target !== null) seek(target)
  }

  function goLive() {
    applyTransition(goLiveTransition(liveEdgeMs, durationInFrames, inputProps.epochMs, inputProps.fps), !reduceMotion)
  }

  const cursorMs = timeForFrame(inputProps.epochMs, currentFrame, inputProps.fps)
  return (
    <div className="overflow-hidden border border-slate-800 bg-slate-950">
      <div className="w-full overflow-x-auto bg-slate-950">
        <div className="aspect-video min-w-[760px]">
          <Player
            ref={playerRef}
            acknowledgeRemotionLicense
            component={ProxyLabComposition}
            compositionHeight={PROXY_COMPOSITION_HEIGHT}
            compositionWidth={PROXY_COMPOSITION_WIDTH}
            controls={false}
            durationInFrames={Math.max(1, durationInFrames)}
            fps={inputProps.fps}
            inputProps={inputProps}
            loop={false}
            moveToBeginningWhenEnded={false}
            numberOfSharedAudioTags={0}
            playbackRate={rate}
            style={{ height: '100%', width: '100%' }}
          />
        </div>
      </div>
      <ActivityDataQuality quality={quality} />
      <div className="space-y-3 border-t border-slate-800 bg-slate-900 p-3">
        <div className="flex flex-wrap items-center gap-2">
          <Control label="Previous event" onClick={() => seekEvent('previous')}><ChevronFirst size={16} /></Control>
          <Control label="Back one second" onClick={() => seek(currentFrame - inputProps.fps)}><Rewind size={16} /></Control>
          <Control label="Back one frame" onClick={() => seek(currentFrame - 1)}><StepBack size={16} /></Control>
          <Control label={isPlaying ? 'Pause' : 'Play'} onClick={togglePlay} primary>{isPlaying ? <Pause size={17} /> : <Play size={17} />}</Control>
          <Control label="Forward one frame" onClick={() => seek(currentFrame + 1)}><StepForward size={16} /></Control>
          <Control label="Forward one second" onClick={() => seek(currentFrame + inputProps.fps)}><FastForward size={16} /></Control>
          <Control label="Next event" onClick={() => seekEvent('next')}><ChevronLast size={16} /></Control>
          <Control active={playback === 'following'} label="Go live" onClick={goLive}><Radio size={16} /></Control>
          <label className="ml-auto flex items-center gap-2 text-xs text-slate-400">
            Speed
            <select
              aria-label="Playback speed"
              className="border border-slate-700 bg-slate-950 px-2 py-1 text-slate-100"
              onChange={(event) => setTimelinePlayback({ rate: Number(event.target.value) })}
              value={rate}
            >
              {rates.map((value) => <option key={value} value={value}>{value}×</option>)}
            </select>
          </label>
        </div>
        <div className="flex items-center gap-3">
          <span className="w-24 shrink-0 font-mono text-[11px] text-slate-400">{formatTime(cursorMs)}</span>
          <div className="min-w-0 flex-1">
            <input
              aria-label="Proxy session scrubber"
              className="block w-full accent-cyan-500"
              max={Math.max(0, durationInFrames - 1)}
              min={0}
              onChange={(event) => seek(Number(event.target.value))}
              type="range"
              value={Math.min(currentFrame, Math.max(0, durationInFrames - 1))}
            />
            <QualityTimeline
              cursorMs={cursorMs}
              endMs={timeForFrame(inputProps.epochMs, Math.max(1, durationInFrames - 1), inputProps.fps)}
              quality={quality}
              startMs={inputProps.epochMs}
            />
          </div>
          <span className="font-mono text-[11px] text-slate-500">frame {currentFrame}</span>
        </div>
      </div>
    </div>
  )
}

function QualityTimeline({ quality, startMs, endMs, cursorMs }: {
  quality: ActivityDataQualityModel
  startMs: number
  endMs: number
  cursorMs: number
}) {
  const durationMs = Math.max(1, endMs - startMs)
  const cursorLeft = percent(cursorMs, startMs, durationMs)
  return (
    <div
      aria-label="Activity quality timeline. Amber ranges are partial capture, red ranges are unavailable capture, and violet ticks are browser live-stream gaps."
      className="relative mt-0.5 h-2 overflow-hidden border border-slate-700 bg-slate-950"
      role="img"
    >
      {quality.captureIntervals.map((interval) => (
        <CaptureInterval key={interval.id} interval={interval} rangeDurationMs={durationMs} rangeStartMs={startMs} />
      ))}
      {quality.streamGapTimes.map((time, index) => {
        const left = percent(time, startMs, durationMs)
        if (left < 0 || left > 100) return null
        return <span className="absolute inset-y-0 z-20 w-0.5 bg-violet-400" key={`${time}:${index}`} style={{ left: `${left}%` }} title={`Live stream gap at ${formatTime(time)}`} />
      })}
      <span aria-hidden className="absolute inset-y-0 z-30 w-px bg-cyan-200" style={{ left: `${Math.min(100, Math.max(0, cursorLeft))}%` }} />
    </div>
  )
}

function CaptureInterval({ interval, rangeStartMs, rangeDurationMs }: {
  interval: CaptureQualityInterval
  rangeStartMs: number
  rangeDurationMs: number
}) {
  const clippedStart = Math.max(rangeStartMs, interval.startMs)
  const clippedEnd = Math.min(rangeStartMs + rangeDurationMs, interval.endMs)
  if (clippedEnd <= clippedStart) return null
  return (
    <span
      className={`absolute inset-y-0 z-10 opacity-90 ${interval.level === 'unavailable' ? 'bg-rose-500' : 'bg-amber-500'}`}
      style={{ left: `${percent(clippedStart, rangeStartMs, rangeDurationMs)}%`, minWidth: '2px', width: `${(clippedEnd - clippedStart) / rangeDurationMs * 100}%` }}
      title={`${interval.level === 'unavailable' ? 'Capture unavailable' : 'Capture partial'} · ${formatTime(interval.startMs)} · ${interval.detail}`}
    />
  )
}

function percent(value: number, startMs: number, durationMs: number) {
  return (value - startMs) / durationMs * 100
}

function Control({ label, onClick, children, primary = false, active = false }: {
  label: string
  onClick: () => void
  children: ReactNode
  primary?: boolean
  active?: boolean
}) {
  return (
    <button
      aria-label={label}
      aria-pressed={label === 'Go live' ? active : undefined}
      className={`grid h-9 w-9 place-items-center border ${primary ? 'border-cyan-500 bg-cyan-700 text-white' : active ? 'border-emerald-500 bg-emerald-950 text-emerald-200' : 'border-slate-700 bg-slate-950 text-slate-300 hover:border-slate-500'}`}
      onClick={onClick}
      title={label}
      type="button"
    >{children}</button>
  )
}

function formatTime(epochMs: number) {
  if (!Number.isFinite(epochMs)) return '--:--:--.---'
  return new Date(epochMs).toISOString().slice(11, 23)
}
