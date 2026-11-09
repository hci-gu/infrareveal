import { useImperativeHandle, useRef, useState } from 'react'
import type { MapRendererProps } from '../map/MapWorkspaceView'
import { EqualEarthMap } from '../map/EqualEarthMap'
import type { EqualEarthControls } from '../map/EqualEarthMap'
import { MapIcon } from '../map/MapIcon'
import { countryFitPositions } from '../map/countryFootprints'

export function EqualEarthComposition({ controlsRef, inspection, preferences, workspace, overview, scene, emptyState }: MapRendererProps) {
  const controls = useRef<EqualEarthControls>(null)
  const [showTraffic, setShowTraffic] = useState(true)
  const { location: selectedLocation, selectLocation } = inspection
  const locations = overview.locations
  useImperativeHandle(controlsRef, () => ({ fit: trackId => {
    const targets = trackId ? locations.filter(location => location.series.some(series => series.trackId === trackId)) : selectedLocation ? [selectedLocation] : locations
    controls.current?.fit([[scene.origin.longitude, scene.origin.latitude], ...targets.flatMap(location => location.country ? countryFitPositions(location.country) : location.position ? [location.position] : [])])
  } }))
  return (
    <div className="atlas-map-surface" hidden={workspace.expanded}>
      <EqualEarthMap controlsRef={controls} locations={locations} origin={scene.origin} selected={selectedLocation?.id ?? null} onSelect={selectLocation} labels={preferences.labels} showTraffic={showTraffic} />
      <div className="atlas-vignette" />
      <div className="atlas-map-heading"><span>NETWORK ATLAS</span><span className="atlas-map-heading-detail">Equal Earth</span></div>
      <div className="atlas-view-options"><button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic(value => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button></div>
      {emptyState}
      <div className="atlas-map-footer"><div className="atlas-legend"><span className="atlas-down"><i className="atlas-direction-swatch" />↓ Downloaded · to your devices</span><span className="atlas-up"><i className="atlas-direction-swatch is-sent" />↑ Sent · from your devices</span>{locations.some(location => location.country) && <span><i className="atlas-country-swatch" />Country estimate</span>}</div><p>Direct connections · country anchors are approximate · Coarse IP locations</p></div>
    </div>
  )
}
