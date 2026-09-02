import type { CallbackListener, PlayerRef } from '@remotion/player'
import { Player } from '@remotion/player'
import { setWorkerUrl } from 'maplibre-gl'
import mapLibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?url'
import 'maplibre-gl/dist/maplibre-gl.css'
import { useCallback, useEffect, useMemo, useRef } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  FPS,
  frameForTime,
  sessionTimelineStore,
  setTimelinePlayback,
  timeForFrame,
  useGatewayData,
} from '@infrareveal/session-state'
import { gatewayOrigin, mapStyleUrl } from '../config'
import { buildMapTimelineScene } from '../map/mapModel'
import { MapComposition } from '../remotion/MapComposition'
import type { MapCompositionProps } from '../remotion/MapComposition'

const COMPOSITION_WIDTH = 1920
const COMPOSITION_HEIGHT = 1080
const LIVE_DURATION_HEADROOM_SECONDS = 30
const LIVE_EDGE_TOLERANCE_MS = 2_000

setWorkerUrl(mapLibreWorkerUrl)

export function MapPage() {
  const { sessionID = '' } = useParams()
  const playerRef = useRef<PlayerRef>(null)
  const initializedSessionRef = useRef<string | null>(null)
  const programmaticSeekTargetRef = useRef<number | null>(null)
  const followingCommandRef = useRef(false)
  const followingCommandTimerRef = useRef(0)
  const lastCursorPublishRef = useRef(0)
  const { connectionState, data, timeline } = useGatewayData(sessionID)
  const scene = useMemo(
    () => buildMapTimelineScene(data, gatewayOrigin, timeline.epochMs),
    [data, timeline.epochMs],
  )
  const contentEndMs = Math.max(scene.startMs + 1_000, scene.endMs, timeline.liveEdgeMs)
  const contentDurationInFrames = Math.max(FPS, frameForTime(scene.startMs, contentEndMs, FPS) + 1)
  const durationInFrames = timeline.mode === 'live'
    ? roundLiveDuration(contentDurationInFrames)
    : contentDurationInFrames
  const timelineRef = useRef({
    epochMs: scene.startMs,
    liveEdgeMs: timeline.liveEdgeMs,
    mode: timeline.mode,
  })

  useEffect(() => {
    timelineRef.current = {
      epochMs: scene.startMs,
      liveEdgeMs: timeline.liveEdgeMs,
      mode: timeline.mode,
    }
  }, [scene.startMs, timeline.liveEdgeMs, timeline.mode])

  const inputProps = useMemo<MapCompositionProps>(() => ({
    scene,
    fps: FPS,
    connectionState,
    timelineMode: timeline.mode,
    playbackState: timeline.playback,
    mapStyleUrl,
  }), [connectionState, scene, timeline.mode, timeline.playback])

  const followLiveEdge = useCallback((forceSeek = false) => {
    const player = playerRef.current
    if (!player || timeline.mode !== 'live') return
    const targetFrame = liveFrame(scene.startMs, timeline.liveEdgeMs, contentDurationInFrames)
    const shouldSeek = forceSeek || Math.abs(player.getCurrentFrame() - targetFrame) > FPS
    const shouldPlay = !player.isPlaying()
    if (shouldSeek || shouldPlay) {
      followingCommandRef.current = true
      window.clearTimeout(followingCommandTimerRef.current)
      followingCommandTimerRef.current = window.setTimeout(() => {
        followingCommandRef.current = false
      }, 250)
    }
    if (shouldSeek) {
      programmaticSeekTargetRef.current = targetFrame
      player.seekTo(targetFrame)
    }
    if (shouldPlay) player.play()
    setTimelinePlayback({
      cursorMs: timeForFrame(scene.startMs, targetFrame, FPS),
      playback: 'following',
    })
  }, [contentDurationInFrames, scene.startMs, timeline.liveEdgeMs, timeline.mode])

  const renderLiveControls = useCallback(() => timeline.mode === 'live' ? (
    <button
      type="button"
      onClick={() => followLiveEdge(true)}
      className={`inline-flex items-center gap-2 rounded-full border px-3 py-1 text-xs font-bold transition focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white ${
        timeline.playback === 'following'
          ? 'border-red-400 bg-red-600 text-white hover:bg-red-500'
          : 'border-slate-500 bg-slate-900 text-white hover:bg-slate-700'
      }`}
      aria-label={timeline.playback === 'following' ? 'Following live; resync to live edge' : 'Go live'}
    >
      <span className={`h-2 w-2 rounded-full bg-current ${timeline.playback === 'following' ? 'animate-pulse' : ''}`} />
      {timeline.playback === 'following' ? 'Live' : 'Go live'}
    </button>
  ) : null, [followLiveEdge, timeline.mode, timeline.playback])

  useEffect(() => () => window.clearTimeout(followingCommandTimerRef.current), [])

  useEffect(() => {
    const player = playerRef.current
    if (!player) return

    const handleFrameUpdate: CallbackListener<'frameupdate'> = (event) => {
      const now = performance.now()
      if (now - lastCursorPublishRef.current < 100) return
      lastCursorPublishRef.current = now
      const current = timelineRef.current
      setTimelinePlayback({ cursorMs: timeForFrame(current.epochMs, event.detail.frame, FPS) })
    }
    const handleSeeked: CallbackListener<'seeked'> = (event) => {
      const expected = programmaticSeekTargetRef.current
      if (expected !== null && Math.abs(expected - event.detail.frame) <= 1) {
        programmaticSeekTargetRef.current = null
        return
      }
      const current = timelineRef.current
      const cursorMs = timeForFrame(current.epochMs, event.detail.frame, FPS)
      const atLiveEdge = current.mode === 'live' && cursorMs >= current.liveEdgeMs - LIVE_EDGE_TOLERANCE_MS
      setTimelinePlayback({
        cursorMs,
        playback: atLiveEdge ? 'following' : player.isPlaying() ? 'playing' : 'paused',
      })
    }
    const handlePlay = () => {
      const current = timelineRef.current
      const cursorMs = timeForFrame(current.epochMs, player.getCurrentFrame(), FPS)
      const alreadyFollowing = sessionTimelineStore.getState().playback === 'following'
      const atLiveEdge = current.mode === 'live' && cursorMs >= current.liveEdgeMs - LIVE_EDGE_TOLERANCE_MS
      setTimelinePlayback({ playback: alreadyFollowing || atLiveEdge ? 'following' : 'playing' })
    }
    const handlePause = () => {
      if (!followingCommandRef.current) setTimelinePlayback({ playback: 'paused' })
    }
    const handleEnded = () => setTimelinePlayback({ playback: 'paused' })
    const handleRateChange: CallbackListener<'ratechange'> = (event) => {
      setTimelinePlayback({ rate: event.detail.playbackRate })
    }

    player.addEventListener('frameupdate', handleFrameUpdate)
    player.addEventListener('seeked', handleSeeked)
    player.addEventListener('play', handlePlay)
    player.addEventListener('pause', handlePause)
    player.addEventListener('ended', handleEnded)
    player.addEventListener('ratechange', handleRateChange)
    return () => {
      player.removeEventListener('frameupdate', handleFrameUpdate)
      player.removeEventListener('seeked', handleSeeked)
      player.removeEventListener('play', handlePlay)
      player.removeEventListener('pause', handlePause)
      player.removeEventListener('ended', handleEnded)
      player.removeEventListener('ratechange', handleRateChange)
    }
  }, [])

  useEffect(() => {
    const player = playerRef.current
    if (!player || !scene.sessionId || initializedSessionRef.current === scene.sessionId) return
    initializedSessionRef.current = scene.sessionId
    if (timeline.mode === 'live') {
      followLiveEdge(true)
      return
    }
    programmaticSeekTargetRef.current = 0
    player.seekTo(0)
    player.play()
    setTimelinePlayback({ cursorMs: scene.startMs, playback: 'playing' })
  }, [followLiveEdge, scene.sessionId, scene.startMs, timeline.mode])

  useEffect(() => {
    const player = playerRef.current
    if (
      !player
      || timeline.mode !== 'live'
      || timeline.playback !== 'following'
      || sessionTimelineStore.getState().playback !== 'following'
    ) return
    followLiveEdge()
  }, [followLiveEdge, timeline.mode, timeline.playback])

  return (
    <main
      className="relative h-screen w-screen overflow-hidden bg-white"
      data-session-id={scene.sessionId ?? ''}
      data-session-state={connectionState}
      data-timeline-mode={timeline.mode}
      data-playback-state={timeline.playback}
    >
      <Link
        to="/"
        className="absolute left-1/2 top-3 z-50 -translate-x-1/2 rounded-full border border-slate-700 bg-slate-950/90 px-4 py-2 text-sm font-semibold text-white shadow-lg backdrop-blur transition hover:bg-slate-800 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-white"
      >
        ← All sessions
      </Link>
      <Player
        ref={playerRef}
        acknowledgeRemotionLicense
        component={MapComposition}
        inputProps={inputProps}
        durationInFrames={durationInFrames}
        fps={FPS}
        compositionWidth={COMPOSITION_WIDTH}
        compositionHeight={COMPOSITION_HEIGHT}
        controls
        autoPlay
        initiallyMuted
        alwaysShowControls
        clickToPlay={false}
        spaceKeyToPlayOrPause
        showVolumeControls={false}
        renderCustomControls={renderLiveControls}
        showPlaybackRateControl={[0.5, 1, 2, 4]}
        playbackRate={timeline.rate}
        style={{ height: '100%', width: '100%' }}
      />
    </main>
  )
}

function roundLiveDuration(contentDurationInFrames: number) {
  const headroom = FPS * LIVE_DURATION_HEADROOM_SECONDS
  return Math.max(FPS, Math.ceil((contentDurationInFrames + headroom) / headroom) * headroom)
}

function liveFrame(epochMs: number, liveEdgeMs: number, contentDurationInFrames: number) {
  return Math.max(0, Math.min(
    contentDurationInFrames - 1,
    frameForTime(epochMs, liveEdgeMs - 500, FPS),
  ))
}
