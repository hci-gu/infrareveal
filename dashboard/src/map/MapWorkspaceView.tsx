import { lazy, memo, Suspense, useEffect, useMemo, useRef } from 'react'
import type { ReactNode, Ref } from 'react'
import type { StyleSpecification } from 'maplibre-gl'
import type { MapTimelineScene } from './mapModel'
import { createTrafficProfileCache, TRAFFIC_BUCKET_MS } from './mapTraffic'
import type { MapTrafficIndex, TrafficProfile } from './mapTraffic'
import type { MapPreferences } from './mapPreferences'
import type { WorkspaceProjection, WorkspaceState } from './mapWorkspace'
import type { DestinationVolumeIndex } from './destinationVolumes'
import type { MapPlaybackClock } from './mapPlaybackClock'
import { seriesTraffic, trackTraffic } from './mapTracks'
import { MapOverview } from './MapOverview'
import { MapTimeline } from './MapTimeline'
import { MapTrackInspector } from './MapTrackInspector'
import { MapLocationInspector } from './MapLocationInspector'
import { useMapInspector } from './useMapInspector'
import { MapIcon } from './MapIcon'
import { MapClientsPill } from './MapClientsPill'
import type { ConnectedClientsState } from './useConnectedClients'

const MapComposition = lazy(() => import('../rendering/MapComposition').then(module => ({ default: module.MapComposition })))

export type MapWorkspaceProps = {
  preferences: MapPreferences
  theme: 'dark' | 'light'
  workspace: WorkspaceState
  overview: WorkspaceProjection
  onWorkspace: (value: WorkspaceState) => void
  onSeekTime: (time: number) => void
  live: boolean
  navigationRevision: number
  timelineDetailIndex?: DestinationVolumeIndex
  endMs: number
  scene: MapTimelineScene
  cursorMs: number
  clock: MapPlaybackClock
  width: number
  height: number
  playbackEpochMs: number
  mapStyleUrl: string | StyleSpecification
  unavailable: boolean
  loading: boolean
  refreshing: boolean
  trafficIndex: MapTrafficIndex
  trafficLoading: boolean
  destinationIndex: DestinationVolumeIndex
  destinationLoading: boolean
  destinationError: boolean
  connectedClients: ConnectedClientsState | null
}

export type MapControls = { fit: (trackId?: string) => void }
export type MapRendererProps = Pick<MapWorkspaceProps, 'preferences' | 'theme' | 'workspace' | 'overview' | 'scene' | 'cursorMs' | 'clock' | 'width' | 'height' | 'playbackEpochMs' | 'mapStyleUrl' | 'trafficLoading' | 'destinationIndex' | 'destinationLoading'> & {
  controlsRef: Ref<MapControls>
  inspection: ReturnType<typeof useMapInspector>
  profiles: Map<string, TrafficProfile>
  trafficAnchorMs: number
  emptyState: ReactNode
}

/** One workspace owns inspection and playback for whichever projection is selected. */
export const MapWorkspace = memo(function MapWorkspace(props: MapWorkspaceProps) {
  const { overview, workspace, onWorkspace, scene, cursorMs, preferences, destinationIndex, destinationLoading, destinationError, refreshing } = props
  const controls = useRef<MapControls>(null)
  const inspection = useMapInspector(overview, workspace)
  const { track, location, tracks, open, selectTrack, selectLocation, closeLocation } = inspection
  const trafficAnchorMs = Math.floor(cursorMs / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS
  const projectProfiles = useMemo(() => createTrafficProfileCache(), [])
  const profiles: Map<string, TrafficProfile> = useMemo(() => projectProfiles(overview.scene, props.trafficIndex, trafficAnchorMs),
    [projectProfiles, overview.scene, props.trafficIndex, trafficAnchorMs])
  useEffect(() => {
    if (!workspace.expanded) return
    const onKey = (event: KeyboardEvent) => {
      if (event.key !== 'Escape' || event.defaultPrevented || document.querySelector('dialog[open], .atlas-filter-drawer[data-open]')) return
      onWorkspace({ ...workspace, expanded: false })
      requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[aria-label="Expand traffic timeline"]')?.focus())
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [workspace, onWorkspace])
  const fit = (trackId?: string) => {
    controls.current?.fit(trackId)
    if (workspace.expanded) onWorkspace({ ...workspace, expanded: false })
  }
  const emptyState = overview.scene.endpoints.length === 0 && !refreshing && <div className="atlas-empty"><MapIcon name="globe" size={30} /><h2>{props.unavailable ? 'Session data unavailable' : props.loading ? 'Connecting to your session' : overview.rows.length ? 'No mapped destinations yet' : 'No matching destinations'}</h2><p>{props.unavailable ? 'Check the gateway connection and try again.' : props.loading ? 'Loading the network view…' : overview.rows.length ? 'Geolocated traffic will appear here as it is observed.' : 'Adjust Filters or move the playhead to see traffic.'}</p></div>
  const rendererProps = { ...props, controlsRef: controls, inspection, profiles, trafficAnchorMs, emptyState }
  return <div className="atlas-composition" data-selected-track={track?.id} data-inspector-open={open || undefined} data-track-count={overview.tracks.length} data-destination-count={overview.locations.filter(location => location.position).length} data-workspace={workspace.expanded ? 'timeline' : 'map'} data-location-filter={workspace.locationId ?? ''}>
    {/* One renderer for every projection; remounting on change keeps deck.gl accessors simple. */}
    <Suspense fallback={<div role="status">Loading map…</div>}><MapComposition key={preferences.projection} {...rendererProps} /></Suspense>
    {!workspace.expanded && <MapClientsPill clients={props.connectedClients} workspace={workspace} onWorkspace={onWorkspace} />}
    <MapOverview capturedToMs={destinationIndex.toMs ?? cursorMs} refreshing={refreshing} data={overview} state={workspace} onChange={onWorkspace} startMs={destinationIndex.fromMs ?? scene.startMs} cursorMs={cursorMs} loading={destinationLoading} error={destinationError} selectedTrack={track?.id ?? null} onTrack={selectTrack} selectedLocation={location?.id ?? null} onLocation={selectLocation} />
    {workspace.expanded && <MapTimeline clock={props.clock} playbackEpochMs={props.playbackEpochMs} live={props.live} navigationRevision={props.navigationRevision} detailIndex={props.timelineDetailIndex} refreshing={refreshing} data={overview} state={workspace} index={destinationIndex} startMs={destinationIndex.fromMs ?? scene.startMs} endMs={props.endMs} cursorMs={cursorMs} onSeek={props.onSeekTime} onTrack={selectTrack} loading={destinationLoading} error={destinationError} />}
    {!track && location && <MapLocationInspector cursorMs={cursorMs} order={workspace.order} refreshing={refreshing} key={location.id} location={location} tracks={tracks} traffic={seriesTraffic(location.series, profiles)} loading={destinationLoading} error={destinationError} trafficLoading={props.trafficLoading} onTrack={selectTrack} onClose={closeLocation} onFit={() => fit()} origin={scene.origin} />}
    {track && <MapTrackInspector cursorMs={cursorMs} order={workspace.order} refreshing={refreshing} key={track.id} track={track} traffic={trackTraffic(track, profiles)} locationLabel={location?.label} onClose={() => selectTrack(null)} onFit={() => fit(track.id)} />}
  </div>
})
