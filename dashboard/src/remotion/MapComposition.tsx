import { memo } from 'react'
import type { StyleSpecification } from 'maplibre-gl'
import type { MapTimelineScene } from '../map/mapModel'
import type { MapTrackCatalog } from '../map/mapTracks'
import type { MapTrafficIndex } from '../map/mapTraffic'
import type { MapPreferences } from '../map/mapPreferences'
import type { WorkspaceProjection, WorkspaceState } from '../map/mapWorkspace'
import type { DestinationVolumeIndex } from '../map/destinationVolumes'
import { EqualEarthComposition } from './EqualEarthComposition'
import { MercatorComposition } from './MercatorComposition'

export type MapCompositionProps = {
  preferences: MapPreferences
  theme: 'dark' | 'light'
  workspace: WorkspaceState
  overview: WorkspaceProjection
  onWorkspace: (value: WorkspaceState) => void
  onSeekTime: (time: number) => void
  endMs: number
  scene: MapTimelineScene
  trackCatalog: MapTrackCatalog
  cursorMs: number
  fps: number
  playbackEpochMs: number
  mapStyleUrl: string | StyleSpecification
  unavailable: boolean
  loading: boolean
  trafficIndex: MapTrafficIndex
  trafficLoading: boolean
  destinationIndex: DestinationVolumeIndex
  destinationLoading: boolean
  destinationError: boolean
}

/** Data-clock updates only. Each projection owns its own preparation and rendering. */
export const MapComposition = memo(function MapComposition(props: MapCompositionProps) {
  return props.preferences.projection === 'equal-earth'
    ? <EqualEarthComposition {...props} /> : <MercatorComposition {...props} />
})
