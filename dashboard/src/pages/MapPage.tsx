import type { DemoStatus } from '@infrareveal/session-state'
import { demoHealthMessage } from './demoHealth'
import { SimulationBanner } from './SimulationBanner'
import { MapPlaybackClock } from '../map/mapPlaybackClock'
import type { PlaybackListener } from '../map/mapPlaybackClock'
import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { Link, useParams } from 'react-router-dom'
import {
  FPS,
  frameForTime,
  sessionTimelineStore,
  setTimelinePlayback,
  timeForFrame,
  useSession,
  useMapWindow,
} from '@infrareveal/session-state'
import { gatewayOrigin, mapStyleUrl } from '../config'
import { buildMapTimelineScene } from '../map/mapModel'
import { MapWorkspace } from '../map/MapWorkspaceView'
import type { MapWorkspaceProps } from '../map/MapWorkspaceView'
import { MapIcon } from '../map/MapIcon'
import { MapTransport } from '../map/MapTransport'
import { formatCursor } from '../map/format'
import { indexMapTraffic } from '../map/mapTraffic'
import { buildMapTrackCatalog, TrackColors } from '../map/mapTracks'
import { createDestinationVolumeCache, indexDestinationVolumes } from '../map/destinationVolumes'
import { ActivityBlockBrowser } from '../map/ActivityBlockBrowser'
import { MapSettings } from '../map/MapSettings'
import { useMapPreferences } from '../map/mapPreferences'
import { DEFAULT_TRAFFIC_FILTERS, projectWorkspace, trafficFilterCount } from '../map/mapWorkspace'
import { TrafficFilters } from '../map/TrafficFilters'
import type { WorkspaceState } from '../map/mapWorkspace'
import type { ActivityOrder } from '../map/activityOrder'
import { createWireWaveformCache } from '../map/wireWaveform'
import { themedAtlasStyle } from '../map/atlasStyle'
import { captureStatus } from '../map/captureStatus'
import '../map/map.css'

const LIVE_DURATION_HEADROOM_SECONDS = 30
const LIVE_EDGE_TOLERANCE_MS = 2_000
const TRAFFIC_ORDER_LABELS: Record<ActivityOrder | 'default', string> = { default: 'Default', latest: 'Latest activity', volume: 'Traffic volume', name: 'Name' }


export function MapPage({ sessionIdOverride, demo }: { sessionIdOverride?: string; demo?: { status: DemoStatus; error: string } } = {}) {
  const { sessionID: routeSessionID = '' } = useParams()
  const sessionID = sessionIdOverride ?? routeSessionID
  const { timeline, refresh } = useSession(sessionID)
  const kiosk = Boolean(demo)
  const { preferences, setPreferences, theme } = useMapPreferences()
  const publishMs = 250
  const [blocksOpen, setBlocksOpen] = useState(false)
  const [filtersOpen, setFiltersOpen] = useState(false)
  const closeFilters = useCallback(() => setFiltersOpen(false), [])
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [view, setView] = useState<WorkspaceState & { sessionId: string }>({ ...DEFAULT_TRAFFIC_FILTERS, sessionId: sessionID, expanded: false })
  const workspace = useMemo<WorkspaceState>(() => ({ ...(view.sessionId === sessionID ? view : { ...DEFAULT_TRAFFIC_FILTERS, expanded: false }), order: (view.sessionId === sessionID ? view.order : undefined) ?? (timeline.mode === 'live' ? 'latest' : undefined) }), [view, sessionID, timeline.mode])
  const historySpan = workspace.windowMs ?? DEFAULT_TRAFFIC_FILTERS.windowMs
  const updateWorkspace = useCallback((next: WorkspaceState) => setView({ ...next, sessionId: sessionID }), [sessionID])
  const pageRef = useRef<HTMLElement>(null)
  const mapContainerRef = useRef<HTMLDivElement>(null)
  const [size, setSize] = useState(() => ({ width: Math.max(320, window.innerWidth), height: Math.max(240, window.innerHeight - 208) }))
  const [currentFrame, setCurrentFrame] = useState(0)
  const [navigationRevision, setNavigationRevision] = useState(0)
  const [fullscreenError, setFullscreenError] = useState('')
  const [fullscreen, setFullscreen] = useState(false)
  const [clock] = useState(() => new MapPlaybackClock(FPS))
  const playerRef = useRef(clock)
  const initializedSessionRef = useRef<string | null>(null)
  const programmaticSeekTargetRef = useRef<number | null>(null)
  const lastCursorPublishRef = useRef(0)
  const { connectionState, error } = timeline
  const trackPalette = useMemo(() => ({ sessionID, colors: new TrackColors() }), [sessionID])
  const playbackEpochMs = timeline.epochMs
  const cursorMs = timeForFrame(playbackEpochMs, currentFrame, FPS)
  const windowAnchor = Math.floor((timeline.manifest ? Math.max(cursorMs, timeline.manifest.retained_from_ms) : 0) / 30_000) * 30_000
  const windowTo = windowAnchor + 30_000
  // Overlap requests so a rolling 30-second view retains its previous capture
  // while the next window loads. Stay within the API's 30-minute request limit.
  const windowFrom = Math.max(timeline.manifest?.retained_from_ms ?? 0, windowTo - Math.min(1_800_000, historySpan + 30_000))
  const bucketMs = timeline.manifest?.policy.bucket_ms ?? 50
  const history = useMapWindow(sessionID, windowFrom, windowTo, ([250, 500, 1000, 2500, 5000].find(ms => ms >= historySpan / 480 && ms % bucketMs === 0 && (timeline.manifest?.policy.chunk_ms ?? 5000) % ms === 0) ?? bucketMs), '', true, `history:${historySpan}`, true)
  const activityAnchor = Math.floor(cursorMs / 5000) * 5000
  const activity = useMapWindow(sessionID, Math.max(windowFrom, activityAnchor - 10_000), activityAnchor + 5000, bucketMs, '', true, `activity:${historySpan}`, true)
  const trackCatalog = useMemo(() => buildMapTrackCatalog(history.window, trackPalette.colors), [history.window, trackPalette])
  const scene = useMemo(() => buildMapTimelineScene(trackCatalog, timeline.manifest, gatewayOrigin), [trackCatalog, timeline.manifest])
  const contentEndMs = Math.max(scene.startMs + 1_000, scene.endMs, timeline.liveEdgeMs)
  const contentDurationInFrames = Math.max(FPS, frameForTime(playbackEpochMs, contentEndMs, FPS) + 1)
  const durationInFrames = timeline.mode === 'live' ? roundLiveDuration(contentDurationInFrames) : contentDurationInFrames
  const trafficIndex = useMemo(() => indexMapTraffic(activity.window.series, activity.window.coverage), [activity.window])
  const volumeCache = useMemo(() => createDestinationVolumeCache(), [])
  const destinationIndex = useMemo(() => volumeCache(history.window), [history.window, volumeCache])
  const timelineDetailIndex = useMemo(() => workspace.expanded && activity.hasData
    ? indexDestinationVolumes(activity.window.series, activity.window.from_ms, activity.window.coverage, activity.window.to_ms) : undefined,
  [workspace.expanded, activity.hasData, activity.window])
  const projectionCursor = timeline.playback === 'paused' ? cursorMs : Math.floor(cursorMs / publishMs) * publishMs
  const overview = useMemo(() => projectWorkspace(trackCatalog, scene, destinationIndex, projectionCursor, workspace), [trackCatalog, scene, destinationIndex, projectionCursor, workspace])
  const waveform = useMemo(() => createWireWaveformCache(), [])
  const playbackBins = useMemo(() => waveform([...overview.bySeries.values()], destinationIndex, { from: scene.startMs, to: contentEndMs }), [waveform, overview.bySeries, destinationIndex, scene.startMs, contentEndMs])
  const captureWarning = captureStatus(timeline.manifest, timeline.liveEdgeMs)
  const demoWarning = demo && (demo.error || demoHealthMessage(demo.status, Date.parse(demo.status.serverNow)))
  const styledMap = useMemo(() => themedAtlasStyle(mapStyleUrl, theme, preferences.labels), [theme, preferences.labels])
  const timelineRef = useRef({
    epochMs: playbackEpochMs,
    liveEdgeMs: timeline.liveEdgeMs,
    mode: timeline.mode,
  })

  useEffect(() => {
    timelineRef.current = {
      epochMs: playbackEpochMs,
      liveEdgeMs: timeline.liveEdgeMs,
      mode: timeline.mode,
    }
  }, [playbackEpochMs, timeline.liveEdgeMs, timeline.mode])

  // Only an expired replay position needs a seek. Ordinary retention ticks
  // must not rewind frames, restart playback, or shift the travelling streams.
  useEffect(() => {
    const player = playerRef.current
    if (!timeline.manifest?.ephemeral || !player || initializedSessionRef.current !== scene.sessionId) return
    if (timeForFrame(playbackEpochMs, player.getCurrentFrame(), FPS) >= scene.startMs) return
    const target = frameForTime(playbackEpochMs, scene.startMs, FPS)
    programmaticSeekTargetRef.current = target
    player.seekTo(target)
    setCurrentFrame(target)
  }, [scene.sessionId, scene.startMs, playbackEpochMs, timeline.manifest?.ephemeral])

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
    const targetFrame = liveFrame(playbackEpochMs, timeline.liveEdgeMs, contentDurationInFrames)
    const shouldSeek = forceSeek || Math.abs(player.getCurrentFrame() - targetFrame) > FPS
    const shouldPlay = !player.isPlaying()
    if (shouldSeek) {
      programmaticSeekTargetRef.current = targetFrame
      player.seekTo(targetFrame)
    }
    if (shouldPlay) player.play()
    setTimelinePlayback({
      cursorMs: timeForFrame(playbackEpochMs, targetFrame, FPS),
      playback: 'following',
      rate: 1,
    })
  }, [contentDurationInFrames, playbackEpochMs, timeline.liveEdgeMs, timeline.mode])

  const seek = useCallback((frame: number, resumeTimeline = false) => {
    if (resumeTimeline) setNavigationRevision(value => value + 1)
    const target = Math.max(frameForTime(playbackEpochMs, scene.startMs, FPS), Math.min(contentDurationInFrames - 1, frame))
    programmaticSeekTargetRef.current = null
    playerRef.current?.seekTo(target)
    setCurrentFrame(target)
  }, [contentDurationInFrames, playbackEpochMs, scene.startMs])

  const seekTime = useCallback((time: number, resumeTimeline = false) => seek(frameForTime(playbackEpochMs, time, FPS), resumeTimeline), [playbackEpochMs, seek])

  const inputProps = useMemo<MapWorkspaceProps>(() => ({
    scene,
    clock, width: size.width, height: size.height,
    playbackEpochMs,
    cursorMs: projectionCursor,
    mapStyleUrl: styledMap,
    preferences, theme, workspace, overview, onWorkspace: updateWorkspace,
    endMs: contentEndMs, onSeekTime: seekTime,
    live: timeline.mode === 'live', navigationRevision, timelineDetailIndex,
    unavailable: !history.hasData && (Boolean(history.error) || connectionState === 'error' || connectionState === 'offline'),
    loading: history.loading || (!scene.sessionId && connectionState !== 'error' && connectionState !== 'offline'),
    refreshing: history.refreshing || (history.hasData && Boolean(history.error)),
    trafficIndex,
    trafficLoading: activity.loading,
    destinationIndex,
    destinationLoading: history.loading,
    destinationError: Boolean(history.error) && !history.hasData,
  }), [timeline.mode, navigationRevision, timelineDetailIndex, clock, size, projectionCursor, activity.loading, connectionState, scene, playbackEpochMs, trafficIndex, destinationIndex, history.loading, history.error, history.hasData, history.refreshing, styledMap, preferences, theme, workspace, overview, updateWorkspace, contentEndMs, seekTime])
  useEffect(() => { clock.configure({ durationInFrames, rate: timeline.rate }) }, [clock, durationInFrames, timeline.rate])
  useEffect(() => () => clock.dispose(), [clock])

  const togglePlayback = useCallback(() => {
    const player = playerRef.current
    if (!player) return
    if (player.isPlaying()) player.pause()
    else {
      setNavigationRevision(value => value + 1)
      if (player.getCurrentFrame() >= contentDurationInFrames - 1) player.seekTo(frameForTime(playbackEpochMs, scene.startMs, FPS))
      player.play()
    }
  }, [contentDurationInFrames, playbackEpochMs, scene.startMs])

  useEffect(() => {
    const onKey = (event: KeyboardEvent) => {
      if (settingsOpen) return
      const target = event.target as HTMLElement | null
      if (event.altKey || event.ctrlKey || event.metaKey || target?.closest('input, select, button, a, textarea, [contenteditable="true"]')) return
      if (event.code === 'Space') { event.preventDefault(); togglePlayback() }
      if (event.code === 'ArrowLeft') { event.preventDefault(); seek((playerRef.current?.getCurrentFrame() ?? 0) - FPS * 10, true) }
      if (event.code === 'ArrowRight') { event.preventDefault(); seek((playerRef.current?.getCurrentFrame() ?? 0) + FPS * 10, true) }
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [seek, togglePlayback, settingsOpen])

  async function toggleFullscreen() {
    setFullscreenError('')
    try {
      if (document.fullscreenElement) await document.exitFullscreen()
      else if (pageRef.current?.requestFullscreen) await pageRef.current.requestFullscreen()
      else setFullscreenError('Fullscreen is not available in this browser.')
    } catch { setFullscreenError('Fullscreen is not available in this browser.') }
  }

  useEffect(() => {
    const syncFullscreen = () => setFullscreen(document.fullscreenElement === pageRef.current)
    document.addEventListener('fullscreenchange', syncFullscreen)
    return () => document.removeEventListener('fullscreenchange', syncFullscreen)
  }, [])

  useEffect(() => {
    const player = playerRef.current
    if (!player) return

    const handleFrameUpdate: PlaybackListener = (event) => {
      const now = performance.now()
      if (now - lastCursorPublishRef.current < publishMs) return
      lastCursorPublishRef.current = now
      setCurrentFrame(event.detail.frame)
      const current = timelineRef.current
      setTimelinePlayback({ cursorMs: timeForFrame(current.epochMs, event.detail.frame, FPS) })
    }
    const handleSeeked: PlaybackListener = (event) => {
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
      const frame = player.getCurrentFrame()
      setCurrentFrame(frame)
      setTimelinePlayback({ cursorMs: timeForFrame(timelineRef.current.epochMs, frame, FPS), playback: 'paused' })
    }
    const handleEnded = () => {
      const frame = player.getCurrentFrame()
      setCurrentFrame(frame)
      // An outage can exhaust the live clock's headroom. Retain live intent so
      // the next accepted server edge restarts it; explicit pause still wins.
      const following = timelineRef.current.mode === 'live' && sessionTimelineStore.getState().playback === 'following'
      setTimelinePlayback({ cursorMs: timeForFrame(timelineRef.current.epochMs, frame, FPS), playback: following ? 'following' : 'paused' })
    }
    const handleRateChange: PlaybackListener = (event) => {
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
  }, [publishMs])

  useEffect(() => {
    const player = playerRef.current
    if (!player || !scene.sessionId || !timeline.manifest || initializedSessionRef.current === scene.sessionId) return
    initializedSessionRef.current = scene.sessionId
    if (timeline.mode === 'live') {
      followLiveEdge(true)
      return
    }
    programmaticSeekTargetRef.current = frameForTime(playbackEpochMs, scene.startMs, FPS)
    player.seekTo(frameForTime(playbackEpochMs, scene.startMs, FPS))
    player.play()
    setTimelinePlayback({ cursorMs: scene.startMs, playback: 'playing' })
  }, [followLiveEdge, scene.sessionId, scene.startMs, playbackEpochMs, timeline.mode, timeline.manifest])

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
      ref={pageRef}
      className={`atlas-page${kiosk ? " atlas-demo" : ""}${workspace.expanded ? " atlas-timeline-open" : ""}`}
      data-theme={theme}
      data-projection={preferences.projection}
      data-session-id={scene.sessionId ?? ''}
      data-session-state={connectionState}
      data-timeline-mode={timeline.mode}
      data-playback-state={timeline.playback}
    >
      <header className="atlas-header">
        <Link to="/" className="atlas-brand" aria-label="InfraReveal — all sessions"><span className="atlas-brand-mark"><MapIcon name="globe" size={23} /></span><span>infra<span>reveal</span><small>NETWORK OBSERVABILITY</small></span></Link>
        <div className="atlas-header-divider" />
        {workspace.expanded && <button type="button" className="atlas-icon-button atlas-mobile-map-return" aria-label="Back to map" title="Back to map" onClick={() => updateWorkspace({ ...workspace, expanded: false })}><MapIcon name="back" size={17} /></button>}
        <nav className="atlas-breadcrumb" aria-label="Breadcrumb"><Link to="/" aria-label="All sessions"><MapIcon name="back" size={15} /><span>Sessions</span></Link><span className="atlas-breadcrumb-slash">/</span><span className="atlas-session-name" title={scene.sessionName}>{scene.sessionName}</span></nav>
        <div className="atlas-header-right">
          <button type="button" className="atlas-icon-button" aria-label="Browse activity blocks" onClick={() => { setBlocksOpen(value => !value); setFiltersOpen(false) }}><MapIcon name="activity" size={17} /><span className="atlas-header-action-label">Activity</span></button>
          <label className="atlas-traffic-order" title="Sort lists and timeline">
            <MapIcon name="sort" size={16} /><span aria-hidden="true">{TRAFFIC_ORDER_LABELS[workspace.order ?? 'default']}</span>
            <select aria-label="Sort traffic" value={workspace.order ?? 'default'} onChange={event => updateWorkspace({ ...workspace, order: event.target.value === 'default' ? undefined : event.target.value as ActivityOrder })}>
              {Object.entries(TRAFFIC_ORDER_LABELS).map(([value, label]) => <option key={value} value={value}>{label}</option>)}
            </select>
          </label>
          <button id="traffic-filters-toggle" type="button" className="atlas-filter-toggle" aria-label="Filters" aria-controls="traffic-filters" aria-expanded={filtersOpen} onClick={() => { setFiltersOpen(value => !value); setBlocksOpen(false) }}><MapIcon name="filter" size={16} /><span>Filters</span>{trafficFilterCount(workspace) > 0 && <small>{trafficFilterCount(workspace)}</small>}</button>
          <button type="button" className="atlas-icon-button" aria-label="Open display settings" title="Display settings" onClick={() => { setSettingsOpen(true); setFiltersOpen(false) }}><MapIcon name="settings" /></button>
          <div className="atlas-clock"><strong>{formatCursor(cursorMs)}</strong></div>
        </div>
      </header>
      {!!timeline.manifest?.simulation_expires_ms && <SimulationBanner key={sessionID} session={sessionID} expiresMS={timeline.manifest.simulation_expires_ms} serverMS={timeline.manifest.server_ms} />}
      {(error || history.error || activity.error) && <div className="atlas-connection-notice" role="status"><span>{error || history.error || activity.error}</span><button type="button" onClick={() => { void refresh(); history.refresh(); activity.refresh() }}>Retry connection</button></div>}
      {captureWarning && <div className="atlas-connection-notice" role="status">{captureWarning}</div>}
      {demoWarning && <div className="atlas-connection-notice" role="status">{demoWarning}</div>}
      <div className="atlas-map-container" data-filters-open={filtersOpen || undefined}>
        <div ref={mapContainerRef} className="atlas-filter-workspace"><MapWorkspace {...inputProps} /></div>
        <TrafficFilters open={filtersOpen} state={workspace} data={overview} onChange={updateWorkspace} onClose={closeFilters} />
      </div>
      {blocksOpen && <ActivityBlockBrowser live={timeline.mode === 'live'} cursorMs={cursorMs} sessionId={sessionID} fromMs={windowFrom} toMs={Math.min(windowTo, contentEndMs)} data={overview} state={workspace} onSeek={seekTime} onClose={() => setBlocksOpen(false)} />}
      <MapSettings open={settingsOpen} preferences={preferences} fullscreen={fullscreen} fullscreenError={fullscreenError} onChange={setPreferences} onToggleFullscreen={() => void toggleFullscreen()} onClose={() => setSettingsOpen(false)} />
      <MapTransport scene={scene} bins={playbackBins} endMs={contentEndMs} frame={frameForTime(scene.startMs, cursorMs, FPS)} fps={FPS}
        playing={timeline.playback === 'playing' || timeline.playback === 'following'} rate={timeline.rate}
        live={timeline.mode === 'live'} following={timeline.playback === 'following'}
        onToggle={togglePlayback} onSeek={frame => seekTime(timeForFrame(scene.startMs, frame, FPS), true)}
        onStep={frames => seek((playerRef.current?.getCurrentFrame() ?? currentFrame) + frames, true)} onRate={(rate) => setTimelinePlayback({
          rate,
          // A faster/slower clock is playback; live following must run at real time.
          ...(rate !== 1 && timeline.playback === 'following' ? { playback: 'playing' } : {}),
        })}
        onLive={() => { setNavigationRevision(value => value + 1); followLiveEdge(true) }} />
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
