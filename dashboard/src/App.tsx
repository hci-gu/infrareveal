import type { CallbackListener, PlayerRef } from '@remotion/player'
import { Player } from '@remotion/player'
import {
  Activity,
  Database,
  FastForward,
  Grid2X2,
  Pause,
  Play,
  Radio,
  Rewind,
  Rows3,
  SkipBack,
  SkipForward,
  Wifi,
  WifiOff,
} from 'lucide-react'
import { useEffect, useMemo, useRef, useState } from 'react'
import type { ReactNode } from 'react'
import { useGatewayData } from './data/useGatewayData'
import {
  COMPOSITION_HEIGHT,
  COMPOSITION_WIDTH,
  FPS,
  buildSessionComposition,
} from './model/sessionModel'
import type { ServiceGroup, TimelineClip } from './model/sessionModel'
import { SessionComposition } from './remotion/SessionComposition'
import type { DashboardViewMode, SessionCompositionProps } from './remotion/SessionComposition'
import { formatBytes, formatClock, formatDateTime, formatDuration } from './views/formatters'

type ZoomPreset = {
  label: string
  frames: number | 'all'
}

type SelectionEvent = CustomEvent<{
  kind: 'clip' | 'service'
  id: string
}>

const zoomPresets: ZoomPreset[] = [
  { label: '1m', frames: FPS * 60 },
  { label: '5m', frames: FPS * 300 },
  { label: 'All', frames: 'all' },
]

function App() {
  const playerRef = useRef<PlayerRef>(null)
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null)
  const { data, connectionState, error } = useGatewayData(selectedSessionId)
  const composition = useMemo(() => buildSessionComposition(data), [data])
  const [viewMode, setViewMode] = useState<DashboardViewMode>('timeline')
  const [currentFrame, setCurrentFrame] = useState(0)
  const [isPlaying, setIsPlaying] = useState(true)
  const [followLive, setFollowLive] = useState(true)
  const [playbackRate, setPlaybackRate] = useState(1)
  const [zoomFrames, setZoomFrames] = useState<number | 'all'>('all')
  const [selectedClipId, setSelectedClipId] = useState<string | null>(null)
  const [selectedServiceId, setSelectedServiceId] = useState<string | null>(null)
  const selectedSessionKey = data.selectedSession?.id ?? 'no-session'

  const selectedClip = useMemo(
    () => composition.clips.find((clip) => clip.id === selectedClipId) ?? null,
    [composition.clips, selectedClipId],
  )
  const activeServiceId = selectedServiceId ?? selectedClip?.serviceGroupId ?? null
  const selectedService = useMemo(
    () => composition.serviceGroups.find((group) => group.id === activeServiceId) ?? null,
    [activeServiceId, composition.serviceGroups],
  )

  const inputProps = useMemo<SessionCompositionProps>(
    () => ({
      composition,
      viewMode,
      zoomFrames,
      selectedClipId,
      selectedServiceId: activeServiceId,
      followLive,
    }),
    [activeServiceId, composition, followLive, selectedClipId, viewMode, zoomFrames],
  )

  useEffect(() => {
    const player = playerRef.current
    if (!player) {
      return
    }

    const handleFrameUpdate: CallbackListener<'frameupdate'> = (event) => {
      setCurrentFrame(event.detail.frame)
    }
    const handlePlay = () => setIsPlaying(true)
    const handlePause = () => setIsPlaying(false)
    const handleEnded = () => setIsPlaying(false)

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
  }, [composition.durationInFrames])

  useEffect(() => {
    const handleSelection = (event: Event) => {
      const detail = (event as SelectionEvent).detail
      if (!detail) {
        return
      }
      if (detail.kind === 'clip') {
        const clip = composition.clips.find((item) => item.id === detail.id)
        setSelectedClipId(detail.id)
        setSelectedServiceId(clip?.serviceGroupId ?? null)
      } else {
        setSelectedClipId(null)
        setSelectedServiceId(detail.id)
      }
    }

    window.addEventListener('infrareveal:select', handleSelection)
    return () => window.removeEventListener('infrareveal:select', handleSelection)
  }, [composition.clips])

  useEffect(() => {
    setSelectedClipId(null)
    setSelectedServiceId(null)

    const player = playerRef.current
    if (data.selectedSession?.active) {
      setFollowLive(true)
      return
    }

    setFollowLive(false)
    player?.seekTo(0)
    setCurrentFrame(0)
  }, [data.selectedSession?.active, selectedSessionKey])

  useEffect(() => {
    const player = playerRef.current
    if (!player || !followLive) {
      return
    }

    const latestFrame = Math.max(0, composition.durationInFrames - 1)
    player.seekTo(latestFrame)
    setCurrentFrame(latestFrame)
    player.play()
  }, [composition.durationInFrames, followLive])

  function togglePlay() {
    const player = playerRef.current
    if (!player) {
      return
    }
    if (player.isPlaying()) {
      player.pause()
      setFollowLive(false)
    } else {
      player.play()
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
    setFollowLive(false)
  }

  function jumpBy(frames: number) {
    seekTo(currentFrame + frames)
  }

  function jumpLive() {
    const player = playerRef.current
    const latestFrame = Math.max(0, composition.durationInFrames - 1)
    setFollowLive(true)
    setCurrentFrame(latestFrame)
    player?.seekTo(latestFrame)
    player?.play()
  }

  function changePlaybackRate(rate: number) {
    setPlaybackRate(rate)
    setFollowLive(false)
  }

  function changeSession(value: string) {
    const nextSessionId = value === 'active' ? null : value
    setSelectedSessionId(nextSessionId)
    setPlaybackRate(1)
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
              onClick={() => setViewMode('timeline')}
            />
            <SegmentedButton
              active={viewMode === 'treemap'}
              icon={<Grid2X2 size={16} />}
              label="Treemap"
              onClick={() => setViewMode('treemap')}
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
              durationInFrames={composition.durationInFrames}
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
                    onClick={() => setZoomFrames(preset.frames)}
                    type="button"
                  >
                    {preset.label}
                  </button>
                ))}
              </div>
            </div>
          </div>
        </div>

        <Inspector
          clip={selectedClip}
          clips={composition.clips}
          service={selectedService}
          services={composition.serviceGroups}
          trafficCountersAvailable={composition.totals.trafficCountersAvailable}
          currentFrame={currentFrame}
          compositionDuration={composition.durationInFrames}
          onSelectClip={(clip) => {
            setSelectedClipId(clip.id)
            setSelectedServiceId(clip.serviceGroupId)
          }}
          onSelectService={(service) => {
            setSelectedClipId(null)
            setSelectedServiceId(service.id)
          }}
        />
      </section>
    </main>
  )
}

function ConnectionPill({ state, error }: { state: string; error: string | null }) {
  const styles =
    state === 'live'
      ? 'border-emerald-200 bg-emerald-50 text-emerald-800'
      : state === 'error'
        ? 'border-red-200 bg-red-50 text-red-800'
        : 'border-amber-200 bg-amber-50 text-amber-800'

  return (
    <div className={`inline-flex h-9 items-center gap-2 border px-3 text-sm font-semibold ${styles}`} title={error ?? state}>
      {state === 'error' ? <WifiOff size={16} /> : <Wifi size={16} />}
      {state === 'live' ? 'Realtime' : state === 'polling' ? 'Polling' : state}
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

function Inspector({
  clip,
  clips,
  service,
  services,
  trafficCountersAvailable,
  currentFrame,
  compositionDuration,
  onSelectClip,
  onSelectService,
}: {
  clip: TimelineClip | null
  clips: TimelineClip[]
  service: ServiceGroup | null
  services: ServiceGroup[]
  trafficCountersAvailable: boolean
  currentFrame: number
  compositionDuration: number
  onSelectClip: (clip: TimelineClip) => void
  onSelectService: (service: ServiceGroup) => void
}) {
  const recentClips = clips.slice().sort((left, right) => right.startFrame - left.startFrame).slice(0, 5)
  const topActivityGroups = services.slice(0, 5)

  return (
    <aside className="border border-slate-200 bg-white">
      <div className="border-b border-slate-200 px-4 py-3">
        <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Inspector</div>
        <div className="mt-1 text-lg font-semibold text-slate-950">
          {clip?.label ?? service?.label ?? 'No selection'}
        </div>
      </div>

      <div className="space-y-5 px-4 py-4">
        <div>
          <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Playback</div>
          <InfoRow label="Frame" value={`${currentFrame} / ${Math.max(0, compositionDuration - 1)}`} />
          <InfoRow label="Mode" value="Remotion player session" />
        </div>

        {clip ? (
          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Selected request clip</div>
            <InfoRow label="Activity" value={clip.serviceGroupLabel} />
            <InfoRow label="Request" value={clip.label} />
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
            <InfoRow label="Confidence" value={clip.confidence} />
            <p className="mt-3 text-sm leading-6 text-slate-600">{clip.explanation}</p>
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

        {topActivityGroups.length ? (
          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Top activities</div>
            <div className="space-y-2">
              {topActivityGroups.map((item) => (
                <button
                  className={`w-full border px-3 py-2 text-left text-sm ${
                    service?.id === item.id
                      ? 'border-slate-950 bg-slate-950 text-white'
                      : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                  }`}
                  key={item.id}
                  onClick={() => onSelectService(item)}
                  type="button"
                >
                  <span className="block truncate font-semibold">{item.label}</span>
                  <span className="mt-1 block text-xs opacity-75">
                    {formatTraffic(item.totalBytes, trafficCountersAvailable)} / {item.flowCount} flows
                  </span>
                </button>
              ))}
            </div>
          </div>
        ) : null}

        {recentClips.length ? (
          <div>
            <div className="mb-2 text-xs font-semibold uppercase tracking-wide text-slate-500">Recent clips</div>
            <div className="space-y-2">
              {recentClips.map((item) => (
                <button
                  className={`w-full border px-3 py-2 text-left text-sm ${
                    clip?.id === item.id
                      ? 'border-sky-700 bg-sky-700 text-white'
                      : 'border-slate-200 bg-white text-slate-800 hover:bg-slate-50'
                  }`}
                  key={item.id}
                  onClick={() => onSelectClip(item)}
                  type="button"
                >
                  <span className="block truncate font-semibold">{item.label}</span>
                  <span className="mt-1 block text-xs opacity-75">
                    {item.destinationPort}/{item.protocol.toUpperCase()} · {formatTraffic(item.bytes, trafficCountersAvailable)}
                  </span>
                </button>
              ))}
            </div>
          </div>
        ) : null}
      </div>
    </aside>
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

export default App
