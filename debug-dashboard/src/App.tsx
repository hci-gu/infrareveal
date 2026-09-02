import type { CallbackListener, PlayerRef } from '@remotion/player'
import { Player } from '@remotion/player'
import {
  Activity,
  Database,
  Download,
  FastForward,
  Grid2X2,
  Pause,
  Play,
  Radio,
  Rewind,
  Rows3,
  Settings,
  SkipBack,
  SkipForward,
  Trash2,
  Wifi,
  WifiOff,
  X,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useStore } from 'zustand'
import {
  frameForTime,
  selectGatewayDataWindow,
  sessionTimelineStore,
  setTimelinePlayback,
  setTimelineUI,
  timeForFrame,
  toggleTimelineServiceCollapsed,
  useFlowActivityRange,
  useGatewayData,
} from '@infrareveal/session-state'
import { clearObservationData } from './data/clearObservationData'
import {
  COMPOSITION_HEIGHT,
  COMPOSITION_WIDTH,
  FPS,
  SessionCompositionProjector,
} from './model/sessionModel'
import type { ServiceGroup, TimelineClip } from './model/sessionModel'
import type { SessionComposition as SessionCompositionModel } from './model/sessionModel'
import { SessionComposition } from './remotion/SessionComposition'
import { createRecordedRenderBundle } from './remotion/renderBundle'
import type { SessionCompositionProps } from './remotion/SessionComposition'
import { selectSceneWindow } from './timeline/selectors/selectSceneWindow'
import { formatBytes, formatClock, formatDateTime, formatDuration } from './views/formatters'

type ZoomPreset = {
  label: string
  frames: number | 'all'
}

type SelectionEvent = CustomEvent<{
  kind: 'clip' | 'service' | 'toggle-service' | 'focus-service' | 'clear-focus'
  id: string
}>

const zoomPresets: ZoomPreset[] = [
  { label: '10s', frames: FPS * 10 },
  { label: '30s', frames: FPS * 30 },
  { label: '1m', frames: FPS * 60 },
  { label: '5m', frames: FPS * 300 },
  { label: 'All', frames: 'all' },
]
const MAX_VISIBLE_FEED_ROWS = 200

function App() {
  const playerRef = useRef<PlayerRef>(null)
  const lastFramePublishRef = useRef(0)
  const lastURLPublishRef = useRef(0)
  const deepLinkAppliedRef = useRef(false)
  const [initialDeepLink] = useState(readTimelineLocation)
  const [baseProjector] = useState(() => new SessionCompositionProjector())
  const [sceneProjector] = useState(() => new SessionCompositionProjector())
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(initialDeepLink.sessionId)
  const { data, connectionState, error, refresh, timeline } = useGatewayData(selectedSessionId)
  const staticBaseComposition = useMemo(
    () => baseProjector.project(data, { sessionStartMs: timeline.epochMs }),
    [baseProjector, data, timeline.epochMs],
  )
  const logicalSessionEndMs = Math.max(staticBaseComposition.sessionEndMs, timeline.liveEdgeMs)
  const baseComposition = useMemo(
    () => extendCompositionTo(staticBaseComposition, logicalSessionEndMs),
    [logicalSessionEndMs, staticBaseComposition],
  )
  const ui = useStore(sessionTimelineStore, (state) => state.ui)
  const {
    viewMode,
    zoomFrames,
    selectedClipId,
    selectedServiceId,
    focusedServiceId,
    collapsedServiceIds,
    inspectorOpen,
  } = ui
  const [currentFrame, setCurrentFrame] = useState(0)
  const [isPlaying, setIsPlaying] = useState(true)
  const followLive = timeline.playback === 'following'
  const playbackRate = timeline.rate
  const [settingsOpen, setSettingsOpen] = useState(false)
  const [clearState, setClearState] = useState<{
    status: 'idle' | 'clearing' | 'done' | 'error'
    message: string
  }>({ status: 'idle', message: '' })

  const focusedBaseService = useMemo(
    () => baseComposition.serviceGroups.find((group) => group.id === focusedServiceId) ?? null,
    [baseComposition.serviceGroups, focusedServiceId],
  )
  const activityRange = useMemo(() => {
    const maximumSpan = 15 * 60 * 1000
    const sessionStart = baseComposition.sessionStartMs
    const sessionEnd = baseComposition.sessionEndMs
    if (focusedBaseService) {
      const end = Math.ceil((focusedBaseService.lastSeenMs + 5000) / 5000) * 5000
      return {
        start: Math.floor(Math.max(focusedBaseService.firstSeenMs, end - maximumSpan) / 5000) * 5000,
        end,
      }
    }
    const requestedSpan = zoomFrames === 'all'
      ? sessionEnd - sessionStart
      : (zoomFrames / FPS) * 1000
    const span = Math.min(maximumSpan, Math.max(60_000, requestedSpan))
    const selectedBaseClip = baseComposition.clips.find((clip) => clip.id === selectedClipId)
    const anchor = selectedBaseClip
      ? selectedBaseClip.startMs + (selectedBaseClip.endMs - selectedBaseClip.startMs) / 2
      : followLive
        ? sessionEnd
        : sessionStart + (currentFrame / FPS) * 1000
    const start = Math.max(sessionStart, anchor - span * 0.82)
    const boundedStart = Math.min(start, Math.max(sessionStart, sessionEnd - span))
    return {
      start: Math.floor(boundedStart / 5000) * 5000,
      end: Math.ceil(Math.min(sessionEnd + 5000, boundedStart + span) / 5000) * 5000,
    }
  }, [baseComposition.clips, baseComposition.sessionEndMs, baseComposition.sessionStartMs, currentFrame, focusedBaseService, followLive, selectedClipId, zoomFrames])
  const detailFlowIds = useMemo(
    () => baseComposition.clips
      .filter((clip) => (!focusedServiceId || clip.serviceGroupId === focusedServiceId) && clip.startMs < activityRange.end && clip.endMs >= activityRange.start)
      .map((clip) => clip.flowId)
      .sort(),
    [activityRange.end, activityRange.start, baseComposition.clips, focusedServiceId],
  )
  const requestedDetailFlowIds = useMemo(
    () => viewMode === 'timeline' && (zoomFrames !== 'all' || focusedServiceId)
      ? detailFlowIds
      : [],
    [detailFlowIds, focusedServiceId, viewMode, zoomFrames],
  )

  useEffect(() => {
    setTimelinePlayback({ viewport: { fromMs: activityRange.start, toMs: activityRange.end } })
  }, [activityRange.end, activityRange.start])

  const activity = useFlowActivityRange(
    data.selectedSession?.id ?? null,
    activityRange.start,
    activityRange.end,
    requestedDetailFlowIds,
  )
  const staticSceneComposition = useMemo(
    () => viewMode === 'treemap' || (zoomFrames === 'all' && !focusedServiceId)
      ? staticBaseComposition
      : sceneProjector.project(
          selectGatewayDataWindow(data, requestedDetailFlowIds, {
            dnsQueries: activity.dnsQueries,
            flowActivityChunks: activity.chunks,
            flowActivityWindows: activity.windows,
          }),
          { sessionStartMs: timeline.epochMs },
        ),
    [activity.chunks, activity.dnsQueries, activity.windows, data, focusedServiceId, requestedDetailFlowIds, sceneProjector, staticBaseComposition, timeline.epochMs, viewMode, zoomFrames],
  )
  const sceneComposition = useMemo(
    () => extendCompositionTo(staticSceneComposition, logicalSessionEndMs),
    [logicalSessionEndMs, staticSceneComposition],
  )
  const sceneWindow = useMemo(
    () => selectSceneWindow(sceneComposition, {
      fromMs: activityRange.start,
      toMs: activityRange.end,
      overview: viewMode === 'treemap' || (zoomFrames === 'all' && !focusedServiceId),
      focusedServiceId,
      selectedClipId,
      loadedRanges: [{
        fromMs: activityRange.start,
        toMs: activityRange.end,
        complete: !activity.error && !activity.loading,
      }],
    }),
    [activity.error, activity.loading, activityRange.end, activityRange.start, focusedServiceId, sceneComposition, selectedClipId, viewMode, zoomFrames],
  )
  const composition = baseComposition
  const playerDurationInFrames = timeline.mode === 'live'
    ? Math.max(FPS, Math.ceil((composition.durationInFrames + FPS * 30) / (FPS * 30)) * FPS * 30)
    : composition.durationInFrames
  const compositionRef = useRef(composition)
  const followLiveRef = useRef(followLive)
  const selectedSessionRef = useRef(data.selectedSession?.id ?? null)

  useEffect(() => {
    compositionRef.current = composition
  }, [composition])

  useEffect(() => {
    followLiveRef.current = followLive
  }, [followLive])

  useEffect(() => {
    selectedSessionRef.current = data.selectedSession?.id ?? null
  }, [data.selectedSession?.id])

  const selectedClip = useMemo(
    () => sceneComposition.clips.find((clip) => clip.id === selectedClipId) ??
      composition.clips.find((clip) => clip.id === selectedClipId) ?? null,
    [composition.clips, sceneComposition.clips, selectedClipId],
  )
  const activeServiceId = selectedServiceId ?? selectedClip?.serviceGroupId ?? null
  const selectedService = useMemo(
    () => composition.serviceGroups.find((group) => group.id === activeServiceId) ?? null,
    [activeServiceId, composition.serviceGroups],
  )

  const inputProps = useMemo<SessionCompositionProps>(
    () => ({
      sceneWindow,
      viewMode,
      zoomFrames,
      selectedClipId,
      selectedServiceId: activeServiceId,
      focusedServiceId,
      collapsedServiceIds,
      followLive,
    }),
    [activeServiceId, collapsedServiceIds, focusedServiceId, followLive, sceneWindow, selectedClipId, viewMode, zoomFrames],
  )

  useEffect(() => {
    const player = playerRef.current
    if (!player) {
      return
    }

    const handleFrameUpdate: CallbackListener<'frameupdate'> = (event) => {
      const now = performance.now()
      if (now - lastFramePublishRef.current < 100) return
      lastFramePublishRef.current = now
      const currentComposition = compositionRef.current
      const frame = Math.min(event.detail.frame, Math.max(0, currentComposition.durationInFrames - 1))
      setCurrentFrame(frame)
      const cursorMs = timeForFrame(currentComposition.sessionStartMs, frame, currentComposition.fps)
      setTimelinePlayback({ cursorMs })
      if (now - lastURLPublishRef.current >= 1000) {
        lastURLPublishRef.current = now
        writeTimelineLocation(selectedSessionRef.current, cursorMs)
      }
    }
    const handlePlay = () => {
      setIsPlaying(true)
      setTimelinePlayback({ playback: followLiveRef.current ? 'following' : 'playing' })
    }
    const handlePause = () => {
      setIsPlaying(false)
      setTimelinePlayback({ playback: 'paused' })
    }
    const handleEnded = () => {
      setIsPlaying(false)
      setTimelinePlayback({ playback: 'paused' })
    }

    player.addEventListener('frameupdate', handleFrameUpdate)
    player.addEventListener('play', handlePlay)
    player.addEventListener('pause', handlePause)
    player.addEventListener('ended', handleEnded)
    setCurrentFrame(player.getCurrentFrame())
    setIsPlaying(player.isPlaying())

    return () => {
      player.removeEventListener('frameupdate', handleFrameUpdate)
      player.removeEventListener('play', handlePlay)
      player.removeEventListener('pause', handlePause)
      player.removeEventListener('ended', handleEnded)
    }
  }, [])

  useEffect(() => {
    if (deepLinkAppliedRef.current || initialDeepLink.cursorMs === null || !data.selectedSession || timeline.liveEdgeMs <= 0) return
    if (initialDeepLink.sessionId && initialDeepLink.sessionId !== data.selectedSession.id) return
    const player = playerRef.current
    if (!player) return
    const frame = Math.max(0, Math.min(
      composition.durationInFrames - 1,
      frameForTime(composition.sessionStartMs, initialDeepLink.cursorMs, composition.fps),
    ))
    deepLinkAppliedRef.current = true
    player.pause()
    player.seekTo(frame)
    setCurrentFrame(frame)
    setTimelinePlayback({
      cursorMs: timeForFrame(composition.sessionStartMs, frame, composition.fps),
      playback: 'paused',
    })
  }, [composition.durationInFrames, composition.fps, composition.sessionStartMs, data.selectedSession, initialDeepLink.cursorMs, initialDeepLink.sessionId, timeline.liveEdgeMs])

  useEffect(() => {
    const handleSelection = (event: Event) => {
      const detail = (event as SelectionEvent).detail
      if (!detail) {
        return
      }
      if (detail.kind === 'toggle-service') {
        toggleTimelineServiceCollapsed(detail.id)
        return
      }
      if (detail.kind === 'clear-focus') {
        setTimelineUI({ focusedServiceId: null })
        return
      }
      if (detail.kind === 'focus-service') {
        const lane = composition.lanes.find((item) => item.serviceGroupId === detail.id)
        const lastFrame = lane
          ? Math.max(...lane.clips.map((clip) => clip.startFrame + clip.durationFrames))
          : composition.durationInFrames - 1
        const focusedFrame = Math.max(0, Math.min(composition.durationInFrames - 1, Math.round(lastFrame)))
        setTimelineUI({
          focusedServiceId: detail.id,
          selectedClipId: null,
          selectedServiceId: detail.id,
          collapsedServiceIds: collapsedServiceIds.filter((id) => id !== detail.id),
          zoomFrames: 'all',
          inspectorOpen: true,
        })
        setTimelinePlayback({ playback: 'paused' })
        playerRef.current?.pause()
        playerRef.current?.seekTo(focusedFrame)
        setIsPlaying(false)
        setCurrentFrame(focusedFrame)
        return
      }
      if (detail.kind === 'clip') {
        const clip = composition.clips.find((item) => item.id === detail.id)
        setTimelineUI({ selectedClipId: detail.id, selectedServiceId: clip?.serviceGroupId ?? null, inspectorOpen: true })
      } else {
        setTimelineUI({ selectedClipId: null, selectedServiceId: detail.id, inspectorOpen: true })
      }
    }

    window.addEventListener('infrareveal:select', handleSelection)
    return () => window.removeEventListener('infrareveal:select', handleSelection)
  }, [collapsedServiceIds, composition.clips, composition.durationInFrames, composition.lanes])

  useEffect(() => {
    const player = playerRef.current
    if (!player || !followLive || sessionTimelineStore.getState().playback !== 'following') {
      return
    }

    const latestFrame = Math.max(0, Math.min(
      composition.durationInFrames - 1,
      frameForTime(composition.sessionStartMs, timeline.liveEdgeMs - 500, composition.fps),
    ))
    if (Math.abs(player.getCurrentFrame() - latestFrame) > composition.fps) {
      player.seekTo(latestFrame)
      setCurrentFrame(latestFrame)
    }
    if (!player.isPlaying()) player.play()
    setTimelinePlayback({ playback: 'following', cursorMs: timeForFrame(composition.sessionStartMs, latestFrame, composition.fps) })
  }, [composition.durationInFrames, composition.fps, composition.sessionStartMs, followLive, timeline.liveEdgeMs])

  function togglePlay() {
    const player = playerRef.current
    if (!player) {
      return
    }
    if (player.isPlaying()) {
      player.pause()
      setTimelinePlayback({ playback: 'paused' })
    } else {
      player.play()
      setTimelinePlayback({ playback: followLive ? 'following' : 'playing' })
    }
  }

  function seekTo(frame: number) {
    const player = playerRef.current
    if (!player) {
      return
    }
    const nextFrame = Math.max(0, Math.min(composition.durationInFrames - 1, Math.round(frame)))
    player.seekTo(nextFrame)
    setCurrentFrame(nextFrame)
    setTimelinePlayback({
      cursorMs: timeForFrame(composition.sessionStartMs, nextFrame, composition.fps),
      playback: 'paused',
    })
  }

  function jumpBy(frames: number) {
    seekTo(currentFrame + frames)
  }

  function jumpLive() {
    const player = playerRef.current
    const latestFrame = Math.max(0, composition.durationInFrames - 1)
    setTimelineUI({ focusedServiceId: null })
    setCurrentFrame(latestFrame)
    player?.seekTo(latestFrame)
    player?.play()
    setTimelinePlayback({
      cursorMs: timeForFrame(composition.sessionStartMs, latestFrame, composition.fps),
      playback: 'following',
    })
  }

  function changePlaybackRate(rate: number) {
    setTimelinePlayback({ rate, playback: 'playing' })
  }

  function changeSession(value: string) {
    const nextSessionId = value === 'active' ? null : value
    setSelectedSessionId(nextSessionId)
    deepLinkAppliedRef.current = true
    writeTimelineLocation(nextSessionId, null)
    setTimelineUI({
      collapsedServiceIds: [],
      selectedClipId: null,
      selectedServiceId: null,
      focusedServiceId: null,
      inspectorOpen: false,
    })
    setTimelinePlayback({
      rate: 1,
      playback: nextSessionId === null ? 'following' : 'paused',
    })
    if (nextSessionId !== null) {
      playerRef.current?.seekTo(0)
      setCurrentFrame(0)
    }
  }

  function selectClip(clip: TimelineClip) {
    setTimelineUI({ selectedClipId: clip.id, selectedServiceId: clip.serviceGroupId, inspectorOpen: true })
  }

  async function clearAllObservationData() {
    if (!window.confirm('Delete all observation and derived activity data from clients, destinations, DNS, flows, associations, packets, routes, and traceroutes?')) {
      return
    }

    setClearState({ status: 'clearing', message: 'Clearing observation data.' })
    try {
      const result = await clearObservationData({
        clearActivityCache: activity.clear,
        refreshGatewayData: refresh,
      })
      const deletedTotal = Object.values(result.deleted).reduce((total, count) => total + count, 0)
      setTimelineUI({ selectedClipId: null, selectedServiceId: null, focusedServiceId: null, inspectorOpen: false })
      setClearState({
        status: 'done',
        message: `Deleted ${deletedTotal.toLocaleString()} records.`,
      })
    } catch (clearError) {
      setClearState({
        status: 'error',
        message: clearError instanceof Error ? clearError.message : 'Failed to clear observation data.',
      })
    }
  }

  function exportRecordedScene() {
    const session = data.selectedSession
    if (!session || timeline.mode !== 'recorded') return
    const bundle = createRecordedRenderBundle(session.id, sceneWindow)
    const blob = new Blob([JSON.stringify(bundle)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = `infrareveal-${session.id}-render-bundle.json`
    document.body.appendChild(anchor)
    anchor.click()
    anchor.remove()
    URL.revokeObjectURL(url)
  }

  return (
    <main className="min-h-screen bg-slate-100 text-slate-950">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex w-full max-w-[1680px] flex-col gap-5 px-5 py-5 lg:flex-row lg:items-center lg:justify-between">
          <div>
            <p className="text-sm font-semibold uppercase tracking-wide text-sky-700">InfraReveal Gateway</p>
            <h1 className="mt-1 text-3xl font-semibold tracking-normal text-slate-950">
              Session playback dashboard
            </h1>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <ConnectionPill state={connectionState} error={error} />
            <SessionSelect
              sessions={data.sessions}
              selectedSessionId={selectedSessionId}
              onChange={changeSession}
            />
            <SegmentedButton
              active={viewMode === 'timeline'}
              icon={<Rows3 size={16} />}
              label="Timeline"
              onClick={() => setTimelineUI({ viewMode: 'timeline' })}
            />
            <SegmentedButton
              active={viewMode === 'treemap'}
              icon={<Grid2X2 size={16} />}
              label="Treemap"
              onClick={() => setTimelineUI({ viewMode: 'treemap' })}
            />
            <SegmentedButton
              active={settingsOpen}
              icon={<Settings size={16} />}
              label="Settings"
              onClick={() => setSettingsOpen(true)}
            />
          </div>
        </div>
      </header>

      <section className="mx-auto grid w-full max-w-[1680px] grid-cols-2 gap-3 px-5 py-4 lg:grid-cols-5">
        <Metric icon={<Activity size={18} />} label="Flows" value={composition.totals.flowCount} />
        <Metric
          icon={<Database size={18} />}
          label="Traffic"
          value={formatTraffic(composition.totals.byteCount, composition.totals.trafficCountersAvailable)}
        />
        <Metric icon={<Rows3 size={18} />} label="Activities" value={composition.serviceGroups.length} />
        <Metric icon={<Radio size={18} />} label="Routes" value={composition.totals.routeCount} />
        <Metric
          icon={<SkipForward size={18} />}
          label={data.selectedSession?.name || 'Duration'}
          value={formatDuration(composition.durationInFrames / composition.fps)}
        />
      </section>

      {error ? (
        <section className="mx-auto w-full max-w-[1680px] px-5">
          <div className="border border-red-200 bg-red-50 px-4 py-3 text-sm text-red-800">{error}</div>
        </section>
      ) : null}

      {activity.error || (composition.captureStatus && (!composition.captureStatus.running || composition.captureStatus.dropped_events > 0)) ? (
        <section className="mx-auto w-full max-w-[1680px] px-5 pb-4">
          <div className="border border-amber-200 bg-amber-50 px-4 py-3 text-sm text-amber-900">
            {activity.error
              ? `Detailed packet activity is unavailable: ${activity.error}`
              : composition.captureStatus?.last_error ||
                `Packet activity capture ${composition.captureStatus?.running ? 'has dropped events' : 'is not running'}; hatched ranges are unknown rather than idle.`}
          </div>
        </section>
      ) : null}

      <section className="mx-auto grid w-full max-w-[1680px] grid-cols-1 gap-4 px-5 pb-5 xl:grid-cols-[minmax(0,1fr)_390px]">
        <div className="overflow-hidden border border-slate-200 bg-white">
          <div className="aspect-video w-full bg-slate-200">
            <Player
              ref={playerRef}
              acknowledgeRemotionLicense
              component={SessionComposition}
              compositionHeight={COMPOSITION_HEIGHT}
              compositionWidth={COMPOSITION_WIDTH}
              controls={false}
              durationInFrames={playerDurationInFrames}
              fps={composition.fps}
              inputProps={inputProps}
              loop={false}
              moveToBeginningWhenEnded={false}
              numberOfSharedAudioTags={0}
              playbackRate={playbackRate}
              style={{ height: '100%', width: '100%' }}
            />
          </div>

          <div className="border-t border-slate-200 bg-white px-4 py-3">
            <div className="flex flex-col gap-3 xl:flex-row xl:items-center">
              <div className="flex items-center gap-2">
                <IconButton label="Back 10s" onClick={() => jumpBy(-FPS * 10)}>
                  <SkipBack size={17} />
                </IconButton>
                <IconButton label="Back 2s" onClick={() => jumpBy(-FPS * 2)}>
                  <Rewind size={17} />
                </IconButton>
                <IconButton label={isPlaying ? 'Pause' : 'Play'} onClick={togglePlay} primary>
                  {isPlaying ? <Pause size={18} /> : <Play size={18} />}
                </IconButton>
                <IconButton label="Forward 2s" onClick={() => jumpBy(FPS * 2)}>
                  <FastForward size={17} />
                </IconButton>
                <IconButton label="Forward 10s" onClick={() => jumpBy(FPS * 10)}>
                  <SkipForward size={17} />
                </IconButton>
                <IconButton label="Live edge" onClick={jumpLive} active={followLive}>
                  <Radio size={17} />
                </IconButton>
              </div>

              <div className="flex min-w-0 flex-1 items-center gap-3">
                <span className="w-20 shrink-0 text-right font-mono text-xs text-slate-500">
                  {formatClock(composition.sessionStartMs + (currentFrame / composition.fps) * 1000)}
                </span>
                <input
                  aria-label="Session scrubber"
                  className="h-2 min-w-0 flex-1 accent-sky-700"
                  max={Math.max(0, composition.durationInFrames - 1)}
                  min={0}
                  onChange={(event) => seekTo(Number(event.target.value))}
                  type="range"
                  value={Math.min(currentFrame, Math.max(0, composition.durationInFrames - 1))}
                />
                <span className="w-20 shrink-0 font-mono text-xs text-slate-500">
                  {formatDuration(currentFrame / composition.fps)}
                </span>
              </div>

              <div className="flex items-center gap-2">
                {[0.5, 1, 2].map((rate) => (
                  <button
                    className={`h-8 min-w-10 border px-2 text-xs font-semibold ${
                      playbackRate === rate
                        ? 'border-sky-700 bg-sky-700 text-white'
                        : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                    }`}
                    key={rate}
                    onClick={() => changePlaybackRate(rate)}
                    type="button"
                  >
                    {rate}x
                  </button>
                ))}
                {zoomPresets.map((preset) => (
                  <button
                    className={`h-8 min-w-10 border px-2 text-xs font-semibold ${
                      zoomFrames === preset.frames
                        ? 'border-slate-900 bg-slate-900 text-white'
                        : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
                    }`}
                    key={preset.label}
                    onClick={() => setTimelineUI({ zoomFrames: preset.frames })}
                    type="button"
                  >
                    {preset.frames === 'all' && focusedServiceId ? 'Domain' : preset.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <LiveFlowFeed
          clips={focusedServiceId
            ? composition.clips.filter((clip) => clip.serviceGroupId === focusedServiceId)
            : composition.clips}
          trafficCountersAvailable={composition.totals.trafficCountersAvailable}
          selectedClipId={selectedClipId}
          onSelectClip={selectClip}
        />

        <Inspector
          clip={selectedClip}
          service={selectedService}
          trafficCountersAvailable={composition.totals.trafficCountersAvailable}
          currentFrame={currentFrame}
          compositionDuration={composition.durationInFrames}
          open={inspectorOpen}
          onClose={() => setTimelineUI({ inspectorOpen: false })}
        />

        <SettingsModal
          canExport={timeline.mode === 'recorded' && Boolean(data.selectedSession)}
          clearState={clearState}
          onClear={clearAllObservationData}
          onClose={() => setSettingsOpen(false)}
          onExport={exportRecordedScene}
          open={settingsOpen}
        />
      </section>
    </main>
  )
}

function ConnectionPill({ state, error }: { state: string; error: string | null }) {
  const styles =
    state === 'live'
      ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
      : state === 'error' || state === 'offline'
        ? 'border-red-200 bg-red-50 text-red-800'
        : 'border-amber-200 bg-amber-50 text-amber-800'

  return (
    <div className={`inline-flex h-9 items-center gap-2 border px-3 text-sm font-semibold ${styles}`} title={error ?? state}>
      {state === 'error' || state === 'offline' ? <WifiOff size={16} /> : <Wifi size={16} />}
      {state === 'live' ? 'Realtime' : state === 'polling' ? 'Polling' : state === 'offline' ? 'Offline cache' : state}
    </div>
  )
}

function Metric({
  icon,
  label,
  value,
}: {
  icon: ReactNode
  label: string
  value: string | number
}) {
  return (
    <div className="border border-slate-200 bg-white px-4 py-3">
      <div className="flex items-center gap-2 text-sm font-medium text-slate-600">
        {icon}
        {label}
      </div>
      <div className="mt-2 text-2xl font-semibold text-slate-950">{value}</div>
    </div>
  )
}

function SessionSelect({
  onChange,
  selectedSessionId,
  sessions,
}: {
  onChange: (sessionId: string) => void
  selectedSessionId: string | null
  sessions: Array<{ id: string; name: string; active: boolean; created: string }>
}) {
  return (
    <select
      aria-label="Session"
      className="h-9 max-w-[260px] border border-slate-200 bg-white px-3 text-sm font-semibold text-slate-700"
      onChange={(event) => onChange(event.target.value)}
      value={selectedSessionId ?? 'active'}
    >
      <option value="active">Live session</option>
      {sessions.map((session) => (
        <option key={session.id} value={session.id}>
          {session.active ? 'Live: ' : ''}
          {session.name || formatDateTime(session.created)}
        </option>
      ))}
    </select>
  )
}

function SegmentedButton({
  active,
  icon,
  label,
  onClick,
}: {
  active: boolean
  icon: ReactNode
  label: string
  onClick: () => void
}) {
  return (
    <button
      className={`inline-flex h-9 items-center gap-2 border px-3 text-sm font-semibold ${
        active
          ? 'border-slate-900 bg-slate-900 text-white'
          : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'
      }`}
      onClick={onClick}
      type="button"
    >
      {icon}
      {label}
    </button>
  )
}

function IconButton({
  active = false,
  children,
  label,
  onClick,
  primary = false,
}: {
  active?: boolean
  children: ReactNode
  label: string
  onClick: () => void
  primary?: boolean
}) {
  const className = primary
    ? 'border-slate-950 bg-slate-950 text-white hover:bg-slate-800'
    : active
      ? 'border-sky-700 bg-sky-700 text-white hover:bg-sky-800'
      : 'border-slate-200 bg-white text-slate-700 hover:bg-slate-50'

  return (
    <button
      aria-label={label}
      className={`inline-flex h-9 w-9 items-center justify-center border ${className}`}
      onClick={onClick}
      title={label}
      type="button"
    >
      {children}
    </button>
  )
}

function SettingsModal({
  canExport,
  clearState,
  onClear,
  onClose,
  onExport,
  open,
}: {
  canExport: boolean
  clearState: {
    status: 'idle' | 'clearing' | 'done' | 'error'
    message: string
  }
  onClear: () => void
  onClose: () => void
  onExport: () => void
  open: boolean
}) {
  if (!open) {
    return null
  }

  return (
    <>
      <button
        aria-label="Close settings"
        className="fixed inset-0 z-40 bg-slate-950/30"
        onClick={onClose}
        type="button"
      />
      <div className="fixed left-1/2 top-20 z-50 w-[min(560px,calc(100vw-32px))] -translate-x-1/2 border border-slate-200 bg-white shadow-2xl">
        <div className="flex items-start justify-between gap-3 border-b border-slate-200 px-5 py-4">
          <div>
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Settings</div>
            <div className="mt-1 text-xl font-semibold text-slate-950">Gateway data</div>
          </div>
          <IconButton label="Close settings" onClick={onClose}>
            <X size={17} />
          </IconButton>
        </div>

        <div className="space-y-5 px-5 py-5">
          <div className="border border-sky-200 bg-sky-50 px-4 py-4">
            <div className="flex items-start gap-3">
              <Download className="mt-0.5 shrink-0 text-sky-700" size={18} />
              <div className="min-w-0">
                <div className="text-sm font-semibold text-sky-950">Export deterministic render bundle</div>
                <p className="mt-2 text-sm leading-6 text-sky-900">
                  Freezes the current recorded SceneWindow as JSON for a repeatable Remotion render.
                </p>
                <button
                  className="mt-4 inline-flex h-9 items-center gap-2 border border-sky-700 bg-sky-700 px-3 text-sm font-semibold text-white hover:bg-sky-800 disabled:cursor-not-allowed disabled:opacity-60"
                  disabled={!canExport}
                  onClick={onExport}
                  type="button"
                >
                  <Download size={16} />
                  {canExport ? 'Download render bundle' : 'Available for recorded sessions'}
                </button>
              </div>
            </div>
          </div>

          <div className="border border-red-200 bg-red-50 px-4 py-4">
            <div className="flex items-start gap-3">
              <Trash2 className="mt-0.5 shrink-0 text-red-700" size={18} />
              <div className="min-w-0">
                <div className="text-sm font-semibold text-red-900">Clear observation data</div>
                <p className="mt-2 text-sm leading-6 text-red-800">
                  Deletes all records from clients, destinations, dns_queries, flow_attributions, activity episodes, flow associations, flows, packets, routes, and traceroutes.
                </p>
                <button
                  className="mt-4 inline-flex h-9 items-center gap-2 border border-red-700 bg-red-700 px-3 text-sm font-semibold text-white hover:bg-red-800 disabled:cursor-not-allowed disabled:opacity-60"
                  disabled={clearState.status === 'clearing'}
                  onClick={onClear}
                  type="button"
                >
                  <Trash2 size={16} />
                  {clearState.status === 'clearing' ? 'Clearing data' : 'Delete all observation data'}
                </button>
              </div>
            </div>
          </div>

          {clearState.message ? (
            <div
              className={`border px-4 py-3 text-sm ${
                clearState.status === 'error'
                  ? 'border-red-200 bg-red-50 text-red-800'
                  : 'border-emerald-200 bg-emerald-50 text-emerald-800'
              }`}
            >
              {clearState.message}
            </div>
          ) : null}
        </div>
      </div>
    </>
  )
}

function LiveFlowFeed({
  clips,
  onSelectClip,
  selectedClipId,
  trafficCountersAvailable,
}: {
  clips: TimelineClip[]
  onSelectClip: (clip: TimelineClip) => void
  selectedClipId: string | null
  trafficCountersAvailable: boolean
}) {
  const orderedClips = useMemo(
    () => clips.slice().sort((left, right) => right.endMs - left.endMs || right.startMs - left.startMs),
    [clips],
  )
  const visibleClips = orderedClips.slice(0, MAX_VISIBLE_FEED_ROWS)

  return (
    <aside className="border border-slate-200 bg-white">
      <div className="flex items-center justify-between border-b border-slate-200 px-4 py-3">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Live flow feed</div>
          <div className="mt-1 text-lg font-semibold text-slate-950">{orderedClips.length.toLocaleString()} flows</div>
        </div>
        <div className="text-right text-xs font-medium text-slate-500">
          {orderedClips.length ? formatDateTime(orderedClips[0].endMs) : 'Waiting'}
        </div>
      </div>

      <div className="max-h-[calc(100vh-300px)] overflow-y-auto">
        {orderedClips.length === 0 ? (
          <div className="px-4 py-8 text-center text-sm text-slate-500">
            Waiting for flow observations.
          </div>
        ) : (
          <div className="divide-y divide-slate-100">
            {visibleClips.map((clip) => {
              const selected = selectedClipId === clip.id
              return (
                <button
                  className={`w-full px-4 py-3 text-left transition ${
                    selected ? 'bg-sky-50' : 'bg-white hover:bg-slate-50'
                  }`}
                  key={clip.id}
                  onClick={() => onSelectClip(clip)}
                  type="button"
                >
                  <div className="flex items-start justify-between gap-3">
                    <div className="min-w-0">
                      <div className="truncate text-sm font-semibold text-slate-950">{clip.label}</div>
                      <div className="mt-1 truncate text-xs text-slate-500">{clip.serviceGroupLabel}</div>
                    </div>
                    <div className="shrink-0 text-right">
                      <div className="font-mono text-xs text-slate-500">{formatClock(clip.endMs)}</div>
                      <div className="mt-1 text-xs font-semibold uppercase text-slate-500">
                        {clip.protocol}/{clip.destinationPort}
                      </div>
                    </div>
                  </div>
                  <div className="mt-2 flex items-center justify-between gap-3 text-xs text-slate-500">
                    <span className="truncate font-mono">{clip.destinationIP}</span>
                    <span className="shrink-0">{formatTraffic(clip.bytes, trafficCountersAvailable)}</span>
                  </div>
                </button>
              )
            })}
            {orderedClips.length > visibleClips.length ? (
              <div className="bg-slate-50 px-4 py-3 text-xs text-slate-500">
                Showing the {MAX_VISIBLE_FEED_ROWS} most recent flows. Focus a domain or time range to narrow the list.
              </div>
            ) : null}
          </div>
        )}
      </div>
    </aside>
  )
}

function Inspector({
  clip,
  service,
  trafficCountersAvailable,
  currentFrame,
  compositionDuration,
  onClose,
  open,
}: {
  clip: TimelineClip | null
  service: ServiceGroup | null
  trafficCountersAvailable: boolean
  currentFrame: number
  compositionDuration: number
  onClose: () => void
  open: boolean
}) {
  if (!open) {
    return null
  }

  return (
    <>
      <button
        aria-label="Close inspector"
        className="fixed inset-0 z-40 bg-slate-950/20"
        onClick={onClose}
        type="button"
      />
      <aside
        className="fixed bottom-0 right-0 top-0 z-50 w-full max-w-[430px] border-l border-slate-200 bg-white shadow-2xl"
      >
        <div className="flex items-start justify-between gap-3 border-b border-slate-200 px-4 py-3">
          <div className="min-w-0">
            <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Inspector</div>
            <div className="mt-1 truncate text-lg font-semibold text-slate-950">
              {clip?.label ?? service?.label ?? 'No selection'}
            </div>
          </div>
          <IconButton label="Close inspector" onClick={onClose}>
            <X size={17} />
          </IconButton>
        </div>

        <div className="h-[calc(100vh-70px)] space-y-5 overflow-y-auto px-4 py-4">
          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Playback</div>
            <InfoRow label="Frame" value={`${currentFrame} / ${Math.max(0, compositionDuration - 1)}`} />
            <InfoRow label="Mode" value="Remotion player session" />
          </div>

          {clip ? (
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Selected connection</div>
              <InfoRow label="Activity" value={clip.serviceGroupLabel} />
              <InfoRow label="Endpoint" value={clip.label} />
              <InfoRow label="Destination socket" value={`${clip.destinationIP}:${clip.destinationPort}`} mono />
              <InfoRow label="Protocol" value={clip.protocol.toUpperCase()} />
              <InfoRow
                label="Traffic"
                value={formatTraffic(clip.bytes, trafficCountersAvailable)}
              />
              <InfoRow
                label="Packets"
                value={trafficCountersAvailable ? clip.packets.toLocaleString() : 'Unavailable'}
              />
              <InfoRow label="Start" value={formatDateTime(clip.startMs)} />
              <InfoRow label="End" value={formatDateTime(clip.endMs)} />
              <InfoRow label="Connection lifetime" value={formatDuration((clip.endMs - clip.startMs) / 1000)} />
              <InfoRow label="Observed active time" value={formatActivityDuration(clip.activity.activeMs)} />
              <InfoRow label="Observed idle time" value={formatActivityDuration(clip.activity.idleMs)} />
              <InfoRow label="Complete capture coverage" value={formatDuration(clip.activity.coveredMs / 1000)} />
              <InfoRow label="Payload sent" value={formatBytes(clip.activity.payloadBytesOut)} />
              <InfoRow label="Payload received" value={formatBytes(clip.activity.payloadBytesIn)} />
              <InfoRow label="Wire bytes sent" value={formatBytes(clip.activity.wireBytesOut)} />
              <InfoRow label="Wire bytes received" value={formatBytes(clip.activity.wireBytesIn)} />
              <InfoRow label="Activity packets" value={`${clip.activity.packetsOut.toLocaleString()} out / ${clip.activity.packetsIn.toLocaleString()} in`} />
              <InfoRow label="Activity resolution" value={clip.activity.bucketMs ? `${clip.activity.bucketMs} ms` : 'Unavailable'} />
              <InfoRow label="Confidence" value={clip.confidence} />
              {!clip.activity.captureAvailable ? (
                <p className="mt-3 border border-slate-300 bg-slate-50 px-3 py-2 text-sm text-slate-700">
                  Detailed packet activity was not loaded or captured for this part of the connection. Blank space is not treated as idle time.
                </p>
              ) : !clip.activity.captureComplete ? (
                <p className="mt-3 border border-amber-200 bg-amber-50 px-3 py-2 text-sm text-amber-900">
                  Packet activity is incomplete for this connection ({clip.activity.droppedEvents.toLocaleString()} dropped capture events). Hatched ranges are unknown, not idle.
                </p>
              ) : null}
              <p className="mt-3 text-sm leading-6 text-slate-600">{clip.explanation}</p>
              <p className="mt-3 text-sm leading-6 text-slate-600">
                Activity marks show encrypted transport movement. A stream may contain several simultaneous application operations, so marks are not individual HTTP requests or response times.
              </p>
              {clip.associationRelationship ? (
                <div className="mt-4 border border-amber-200 bg-amber-50 px-3 py-3">
                  <div className="text-xs font-semibold uppercase tracking-wide text-amber-800">Website association</div>
                  <InfoRow label="Relationship" value={formatAssociationRelationship(clip.associationRelationship)} />
                  <InfoRow label="Association confidence" value={clip.associationConfidence ?? 'Unknown'} />
                  <InfoRow label="Evidence score" value={clip.associationScore?.toString() ?? 'Unavailable'} />
                  <p className="mt-2 text-sm leading-6 text-amber-900">{clip.associationExplanation}</p>
                </div>
              ) : null}
            </div>
          ) : null}

          {service ? (
            <div>
              <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">
                Activity section
              </div>
              <InfoRow label="Site / app" value={service.label} />
              <InfoRow label="Source" value={service.sourceSignal} />
              <InfoRow label="Provider" value={service.providerLabel || 'Unknown'} />
              <InfoRow label="Flows" value={service.flowCount.toLocaleString()} />
              <InfoRow label="Associated flows" value={service.associatedFlowCount.toLocaleString()} />
              <InfoRow
                label="Traffic"
                value={formatTraffic(service.totalBytes, trafficCountersAvailable)}
              />
              <InfoRow
                label="Packets"
                value={trafficCountersAvailable ? service.packetCount.toLocaleString() : 'Unavailable'}
              />
              <InfoRow label="Observed hostnames" value={service.hostnames.length.toLocaleString()} />
              <InfoRow label="Destinations" value={service.destinationIPs.length.toLocaleString()} />
              <InfoRow label="Devices" value={service.clientIPs.length.toLocaleString()} />
              <InfoRow
                label="Routes"
                value={`${service.routeCompleteCount}/${service.routeCount} complete`}
              />
              <InfoRow label="First seen" value={formatDateTime(service.firstSeenMs)} />
              <InfoRow label="Last seen" value={formatDateTime(service.lastSeenMs)} />
            </div>
          ) : null}

          {!clip && !service ? (
            <div className="border border-dashed border-slate-300 px-4 py-8 text-center text-sm text-slate-500">
              Select a timeline clip or activity section to inspect how it was inferred.
            </div>
          ) : null}
        </div>
      </aside>
    </>
  )
}

function InfoRow({ label, mono = false, value }: { label: string; mono?: boolean; value: string }) {
  return (
    <div className="flex items-start justify-between gap-3 border-b border-slate-100 py-2 text-sm">
      <span className="shrink-0 text-slate-500">{label}</span>
      <span className={`min-w-0 text-right font-medium text-slate-900 ${mono ? 'font-mono text-xs' : ''}`}>
        {value}
      </span>
    </div>
  )
}

function formatTraffic(bytes: number, countersAvailable: boolean) {
  return countersAvailable ? formatBytes(bytes) : 'Counters unavailable'
}

function formatActivityDuration(milliseconds: number) {
  if (milliseconds > 0 && milliseconds < 1000) return `${Math.round(milliseconds)} ms`
  return formatDuration(milliseconds / 1000)
}

function formatAssociationRelationship(relationship: TimelineClip['associationRelationship']) {
  switch (relationship) {
    case 'first_party':
      return 'Confirmed first-party'
    case 'cname_related':
      return 'CNAME-linked infrastructure'
    case 'temporally_associated':
      return 'Temporally associated'
    default:
      return 'None'
  }
}

function readTimelineLocation() {
  if (typeof window === 'undefined') return { sessionId: null as string | null, cursorMs: null as number | null }
  const params = new URLSearchParams(window.location.search)
  const cursor = Number(params.get('at'))
  return {
    sessionId: params.get('session'),
    cursorMs: Number.isFinite(cursor) && cursor > 0 ? cursor : null,
  }
}

function writeTimelineLocation(sessionId: string | null, cursorMs: number | null) {
  if (typeof window === 'undefined') return
  const url = new URL(window.location.href)
  if (sessionId) url.searchParams.set('session', sessionId)
  else url.searchParams.delete('session')
  if (cursorMs !== null) url.searchParams.set('at', String(Math.round(cursorMs)))
  else url.searchParams.delete('at')
  if (url.href !== window.location.href) window.history.replaceState(null, '', url)
}

function extendCompositionTo(composition: SessionCompositionModel, endMs: number): SessionCompositionModel {
  const sessionEndMs = Math.max(composition.sessionEndMs, endMs, composition.sessionStartMs + 1)
  const durationInFrames = Math.max(1, Math.ceil(((sessionEndMs - composition.sessionStartMs) / 1000) * composition.fps))
  if (sessionEndMs === composition.sessionEndMs && durationInFrames === composition.durationInFrames) return composition
  return { ...composition, sessionEndMs, durationInFrames }
}

export default App
