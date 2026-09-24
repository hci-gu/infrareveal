import type { DemoStatus } from '@infrareveal/session-state'
import { demoHealthMessage } from './demoHealth'
import type { CallbackListener, PlayerRef } from '@remotion/player'
import { Player } from '@remotion/player'
import { setWorkerUrl } from 'maplibre-gl'
// Bundle the worker's imports too; ?url alone copies an incomplete ESM entry.
import mapLibreWorkerUrl from 'maplibre-gl/dist/maplibre-gl-worker.mjs?worker&url'
import 'maplibre-gl/dist/maplibre-gl.css'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  FPS,
  frameForTime,
  sessionTimelineStore,
  setTimelinePlayback,
  timeForFrame,
  useGatewayData,
  useFlowActivityRange,
} from '@infrareveal/session-state'
import { gatewayOrigin, mapStyleUrl } from '../config'
import { buildMapTimelineScene } from '../map/mapModel'
import { MapCompositionFromContext, MapCompositionProvider } from '../remotion/MapCompositionProvider'
import type { MapCompositionProps } from '../remotion/MapComposition'
import { MapIcon } from '../map/MapIcon'
import { MapTransport } from '../map/MapTransport'
import { formatCursor } from '../map/format'
import { indexMapTraffic } from '../map/mapTraffic'
import { buildMapTrackCatalog, TrackColors } from '../map/mapTracks'
import { useDestinationVolumes } from '../map/useDestinationVolumes'
import { MapSettings } from '../map/MapSettings'
import { useMapPreferences } from '../map/mapPreferences'
import { projectWorkspace } from '../map/mapWorkspace'
import type { WorkspaceState } from '../map/mapWorkspace'
import { wireWaveform } from '../map/wireWaveform'
import { themedAtlasStyle } from '../map/atlasStyle'
import '../map/map.css'
import '../map/workspace.css'

const LIVE_DURATION_HEADROOM_SECONDS = 30
const LIVE_EDGE_TOLERANCE_MS = 2_000

setWorkerUrl(mapLibreWorkerUrl)

export function MapPage({ sessionIdOverride, demo }: { sessionIdOverride?: string; demo?: { status: DemoStatus; error: string } } = {}) {
  const { sessionID: routeSessionID = '' } = useParams()
  const sessionID = sessionIdOverride ?? routeSessionID
  const kiosk = Boolean(demo)
  const { preferences, setPreferences, theme } = useMapPreferences()
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [view, setView] = useState<WorkspaceState & { sessionId: string }>({ sessionId: sessionID, direction: 'both', locationId: null, expanded: false })
  const workspace = useMemo<WorkspaceState>(() => view.sessionId === sessionID ? view : { direction: view.direction, locationId: null, expanded: false }, [view, sessionID])
  const updateWorkspace = useCallback((next: WorkspaceState) => setView({ ...next, sessionId: sessionID }), [sessionID])
  const pageRef = useRef<HTMLElement>(null)
  const mapContainerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState(() => ({ width: Math.max(320, window.innerWidth), height: Math.max(240, window.innerHeight - 208) }))
  const [currentFrame, setCurrentFrame] = useState(0)
  const [fullscreenError, setFullscreenError] = useState('')
  const playerRef = useRef<PlayerRef>(null)
  const initializedSessionRef = useRef<string | null>(null)
  const programmaticSeekTargetRef = useRef<number | null>(null)
  const followingCommandRef = useRef(false)
  const followingCommandTimerRef = useRef(0)
  const lastCursorPublishRef = useRef(0)
  const { connectionState, data, timeline, error, refresh } = useGatewayData(sessionID)
  const trackPalette = useMemo(() => ({ sessionID, colors: new TrackColors() }), [sessionID])
  const activityStartMs = timeline.epochMs + Math.floor(currentFrame / FPS / 30) * 30_000 - 30_000
  const activity = useFlowActivityRange(data.selectedSession?.id ?? null, activityStartMs, activityStartMs + 90_000)
  const routeData = useMemo(() => ({...data, routes: [...new Map([...data.routes, ...activity.routes].map(route => [route.id, route])).values()]}), [data, activity.routes])
  const scene = useMemo(
    () => buildMapTimelineScene(routeData, gatewayOrigin, timeline.epochMs),
    [routeData, timeline.epochMs],
  )
  const contentEndMs = Math.max(scene.startMs + 1_000, scene.endMs, timeline.liveEdgeMs)
  const contentDurationInFrames = Math.max(FPS, frameForTime(scene.startMs, contentEndMs, FPS) + 1)
  // Playback needs a little headroom between clock ticks to avoid emitting
  // 'ended' at the live edge. The visible transport still uses contentEndMs.
  const durationInFrames = timeline.mode === 'live'
    ? timeline.manifest?.ephemeral ? contentDurationInFrames + FPS * 3 : roundLiveDuration(contentDurationInFrames)
    : contentDurationInFrames
  // Request a bounded 90-second window at 500 ms LOD, moving every 30 seconds.
  const trackCatalog = useMemo(() => buildMapTrackCatalog({ ...routeData, dnsQueries: activity.dnsQueries }, trackPalette.colors), [activity.dnsQueries, routeData, trackPalette])
  const trafficIndex = useMemo(() => indexMapTraffic(activity.chunks), [activity.chunks])
  const destinationVolumes = useDestinationVolumes(scene.sessionId, timeline.mode === 'live', timeline.manifest?.ephemeral, timeline.epochMs)
  const cursorMs = timeForFrame(scene.startMs, currentFrame, FPS)
  const projectionCursor = Math.floor(cursorMs / 250) * 250
  const overview = useMemo(() => projectWorkspace(trackCatalog, scene, destinationVolumes.index, projectionCursor, workspace), [trackCatalog, scene, destinationVolumes.index, projectionCursor, workspace])
  const playbackBins = useMemo(() => wireWaveform([...overview.byFlow.values()], destinationVolumes.index, { from: scene.startMs, to: contentEndMs }), [overview.byFlow, destinationVolumes.index, scene.startMs, contentEndMs])
  const styledMap = useMemo(() => themedAtlasStyle(mapStyleUrl, theme, preferences.labels), [theme, preferences.labels])
  const previousEpoch = useRef(scene.startMs)
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

  // Rebase the player when the rolling origin moves, preserving absolute
  // paused/replay time. Expired paused positions clamp to the retained edge.
  useEffect(() => {
    const oldEpoch = previousEpoch.current
    previousEpoch.current = scene.startMs
    const player = playerRef.current
    if (!timeline.manifest?.ephemeral || !player || oldEpoch === scene.startMs) return
    const absolute = timeForFrame(oldEpoch, player.getCurrentFrame(), FPS)
    const target = Math.min(contentDurationInFrames - 1, frameForTime(scene.startMs, absolute, FPS))
    programmaticSeekTargetRef.current = target
    player.seekTo(target)
    setCurrentFrame(target)
  }, [scene.startMs, contentDurationInFrames, timeline.manifest?.ephemeral])


  useEffect(() => {
    const container = mapContainerRef.current
    if (!container) return
    const observer = new ResizeObserver(([entry]) => {
      const { width, height } = entry.contentRect
      if (width > 0 && height > 0) setSize({ width: Math.round(width), height: Math.round(height) })
    })
    observer.observe(container)
    return () => observer.disconnect()
  }, [])

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
      rate: 1,
    })
  }, [contentDurationInFrames, scene.startMs, timeline.liveEdgeMs, timeline.mode])

  const seek = useCallback((frame: number) => {
    const target = Math.max(0, Math.min(contentDurationInFrames - 1, frame))
    programmaticSeekTargetRef.current = null
    playerRef.current?.seekTo(target)
    setCurrentFrame(target)
  }, [contentDurationInFrames])

  const seekTime = useCallback((time: number) => seek(frameForTime(scene.startMs, time, FPS)), [scene.startMs, seek])

  const inputProps = useMemo<MapCompositionProps>(() => ({
    scene,
    trackCatalog,
    fps: FPS,
    mapStyleUrl: styledMap,
    preferences, theme, workspace, overview, onWorkspace: updateWorkspace,
    endMs: contentEndMs, onSeekTime: seekTime,
    unavailable: connectionState === 'error' || connectionState === 'offline',
    loading: !scene.sessionId && connectionState !== 'error' && connectionState !== 'offline',
    trafficIndex,
    trafficLoading: activity.loading,
    destinationIndex: destinationVolumes.index,
    destinationLoading: destinationVolumes.loading,
    destinationError: destinationVolumes.error,
  }), [activity.loading, connectionState, scene, trackCatalog, trafficIndex, destinationVolumes.index, destinationVolumes.loading, destinationVolumes.error, styledMap, preferences, theme, workspace, overview, updateWorkspace, contentEndMs, seekTime])
  const togglePlayback = useCallback(() => {
    const player = playerRef.current
    if (!player) return
    if (player.isPlaying()) player.pause()
    else {
      if (player.getCurrentFrame() >= contentDurationInFrames - 1) player.seekTo(0)
      player.play()
    }
  }, [contentDurationInFrames])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if ((kiosk && !workspace.expanded) || settingsOpen) return
      const target = event.target as HTMLElement | null
      if (event.altKey || event.ctrlKey || event.metaKey || target?.closest('input, select, button, a, textarea, [contenteditable="true"]')) return
      if (event.code === 'Space') { event.preventDefault(); togglePlayback() }
      if (event.code === 'ArrowLeft') { event.preventDefault(); seek((playerRef.current?.getCurrentFrame() ?? 0) - FPS * 10) }
      if (event.code === 'ArrowRight') { event.preventDefault(); seek((playerRef.current?.getCurrentFrame() ?? 0) + FPS * 10) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [seek, togglePlayback, kiosk, workspace.expanded, settingsOpen])

  async function toggleFullscreen() {
    try {
      if (document.fullscreenElement) await document.exitFullscreen()
      else if (pageRef.current?.requestFullscreen) await pageRef.current.requestFullscreen()
      else setFullscreenError('Fullscreen is not available in this browser.')
    } catch { setFullscreenError('Fullscreen is not available in this browser.') }
  }

  useEffect(() => () => window.clearTimeout(followingCommandTimerRef.current), [])

  useEffect(() => {
    const player = playerRef.current
    if (!player) return

    const handleFrameUpdate: CallbackListener<'frameupdate'> = (event) => {
      const now = performance.now()
      if (now - lastCursorPublishRef.current < 100) return
      lastCursorPublishRef.current = now
      setCurrentFrame(event.detail.frame)
      const current = timelineRef.current
      setTimelinePlayback({ cursorMs: timeForFrame(current.epochMs, event.detail.frame, FPS) })
    }
    const handleSeeked: CallbackListener<'seeked'> = (event) => {
      setCurrentFrame(event.detail.frame)
      const expected = programmaticSeekTargetRef.current
      if (expected !== null && Math.abs(expected - event.detail.frame) <= 1) {
        programmaticSeekTargetRef.current = null
        return
      }
      const current = timelineRef.current
      const cursorMs = timeForFrame(current.epochMs, event.detail.frame, FPS)
      const atLiveEdge = current.mode === 'live' && sessionTimelineStore.getState().rate === 1 && cursorMs >= current.liveEdgeMs - LIVE_EDGE_TOLERANCE_MS
      setTimelinePlayback({
        cursorMs,
        playback: atLiveEdge ? 'following' : player.isPlaying() ? 'playing' : 'paused',
      })
    }
    const handlePlay = () => {
      const current = timelineRef.current
      const cursorMs = timeForFrame(current.epochMs, player.getCurrentFrame(), FPS)
      const alreadyFollowing = sessionTimelineStore.getState().playback === 'following'
      const atLiveEdge = current.mode === 'live' && sessionTimelineStore.getState().rate === 1 && cursorMs >= current.liveEdgeMs - LIVE_EDGE_TOLERANCE_MS
      setTimelinePlayback({ playback: alreadyFollowing || atLiveEdge ? 'following' : 'playing' })
    }
    const handlePause = () => {
      if (!followingCommandRef.current) setTimelinePlayback({ playback: 'paused' })
    }
    const handleEnded = () => {
      const frame = player.getCurrentFrame()
      setCurrentFrame(frame)
      setTimelinePlayback({ cursorMs: timeForFrame(timelineRef.current.epochMs, frame, FPS), playback: 'paused' })
    }
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
    if (!player || !scene.sessionId || !timeline.manifest || initializedSessionRef.current === scene.sessionId) return
    initializedSessionRef.current = scene.sessionId
    if (timeline.mode === 'live') {
      followLiveEdge(true)
      return
    }
    programmaticSeekTargetRef.current = 0
    player.seekTo(0)
    player.play()
    setTimelinePlayback({ cursorMs: scene.startMs, playback: 'playing' })
  }, [followLiveEdge, scene.sessionId, scene.startMs, timeline.mode, timeline.manifest])

  useEffect(() => {
    const player = playerRef.current
    if (
      !player
      || timeline.mode !== 'live'
      || ((!kiosk || workspace.expanded) && (timeline.playback !== 'following'
      || sessionTimelineStore.getState().playback !== 'following'))
    ) return
    followLiveEdge()
  }, [followLiveEdge, timeline.mode, timeline.playback, kiosk, workspace.expanded])

  return (
    <main
      ref={pageRef}
      className={`atlas-page${kiosk ? " atlas-demo" : ""}${workspace.expanded ? " atlas-timeline-open" : ""}`}
      data-theme={theme}
      data-projection={preferences.projection}
      data-direction={workspace.direction}
      data-session-id={scene.sessionId ?? ''}
      data-session-state={connectionState}
      data-timeline-mode={timeline.mode}
      data-playback-state={timeline.playback}
    >
      <header className="atlas-header">
        <Link to="/" className="atlas-brand" aria-label="InfraReveal — all sessions"><span className="atlas-brand-mark"><MapIcon name="globe" size={23} /></span><span>infra<span>reveal</span><small>NETWORK OBSERVABILITY</small></span></Link>
        <div className="atlas-header-divider" />
        <nav className="atlas-breadcrumb" aria-label="Breadcrumb"><Link to="/" aria-label="All sessions"><MapIcon name="back" size={15} /><span>Sessions</span></Link><span className="atlas-breadcrumb-slash">/</span><span className="atlas-session-name" title={scene.sessionName}>{scene.sessionName}</span></nav>
        <div className="atlas-header-right"><button type="button" className="atlas-icon-button" aria-label="Open display settings" title="Display settings" onClick={() => setSettingsOpen(true)}><MapIcon name="settings" /></button><span className={`atlas-status ${connectionState === 'error' || connectionState === 'offline' ? 'is-warning' : ''}`}><i className="atlas-dot" />{connectionState === 'error' || connectionState === 'offline' ? 'Connection lost' : !scene.sessionId ? 'Connecting' : timeline.mode === 'live' ? timeline.playback !== 'following' ? 'Behind live' : connectionState === 'live' ? 'Live session' : connectionState : 'Recorded session'}</span><div className="atlas-clock"><strong>{formatCursor(timeForFrame(scene.startMs, currentFrame, FPS))}</strong><span>UTC</span></div></div>
      </header>
      {(error || fullscreenError) && <div className="atlas-connection-notice" role="status"><span>{error || fullscreenError}</span>{error ? <button type="button" onClick={() => void refresh()}>Retry connection</button> : <button type="button" onClick={() => setFullscreenError('')}>Dismiss</button>}</div>}
      {demo && <div className="atlas-demo-banner">
        <span>Connect to <strong>{demo.status.ssid}</strong> Wi-Fi to see your traffic here</span>
        <span>Last {demo.status.retentionMinutes} minutes · Live network metadata</span>
        {(demo.error || demoHealthMessage(demo.status, Date.parse(demo.status.serverNow))) && <strong role="status" className="atlas-demo-warning">{demo.error || demoHealthMessage(demo.status, Date.parse(demo.status.serverNow))}</strong>}
      </div>}
      <div ref={mapContainerRef} className="atlas-map-container">
      <MapCompositionProvider value={inputProps}>
      <Player
        ref={playerRef}
        acknowledgeRemotionLicense
        component={MapCompositionFromContext}
        durationInFrames={durationInFrames}
        fps={FPS}
        compositionWidth={size.width}
        compositionHeight={size.height}
        controls={false}
        autoPlay
        moveToBeginningWhenEnded={false}
        initiallyMuted
        clickToPlay={false}
        doubleClickToFullscreen={false}
        spaceKeyToPlayOrPause={false}
        showVolumeControls={false}
        playbackRate={timeline.rate}
        style={{ height: '100%', width: '100%' }}
      />
      </MapCompositionProvider>
      </div>
      <MapSettings open={settingsOpen} preferences={preferences} onChange={setPreferences} onClose={() => setSettingsOpen(false)} />
      {(!kiosk || workspace.expanded) && <MapTransport scene={scene} bins={playbackBins} direction={workspace.direction} endMs={contentEndMs} frame={currentFrame} fps={FPS}
        playing={timeline.playback === 'playing' || timeline.playback === 'following'} rate={timeline.rate}
        live={timeline.mode === 'live'} following={timeline.playback === 'following'}
        onToggle={togglePlayback} onSeek={seek} onRate={(rate) => setTimelinePlayback({
          rate,
          // A faster/slower clock is playback; live following must run at real time.
          ...(rate !== 1 && timeline.playback === 'following' ? { playback: 'playing' } : {}),
        })}
        onLive={() => followLiveEdge(true)} onFullscreen={() => void toggleFullscreen()} />}
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
