import { useEffect, useMemo, useRef, useState } from 'react'
import type { MapCompositionProps } from './MapComposition'
import { EqualEarthMap } from '../map/EqualEarthMap'
import type { EqualEarthControls } from '../map/EqualEarthMap'
import { MapOverview } from '../map/MapOverview'
import { MapTimeline } from '../map/MapTimeline'
import { MapTrackInspector } from '../map/MapTrackInspector'
import { MapLocationInspector } from '../map/MapLocationInspector'
import { useMapInspector } from '../map/useMapInspector'
import { MapIcon } from '../map/MapIcon'
import { directionLabel } from '../map/mapWorkspace'
import { countryFitPositions } from '../map/countryFootprints'
import { projectTrafficProfiles, TRAFFIC_BUCKET_MS } from '../map/mapTraffic'
import { seriesTraffic, trackTraffic } from '../map/mapTracks'

/** Equal Earth needs locations and totals, never a Mercator scene or tube geometry. */
export function EqualEarthComposition({ live, following, onFollowLive, timelineDetailIndex, onInspectorChange, preferences, workspace, overview, onWorkspace, onSeekTime, cursorMs, endMs, scene, unavailable, loading, refreshing, trafficIndex, trafficLoading, destinationIndex, destinationLoading, destinationError }: MapCompositionProps) {
  const controls = useRef<EqualEarthControls>(null)
  const [activeOnly, setActiveOnly] = useState(false)
  const [showTraffic, setShowTraffic] = useState(true)
  const { track: selected, location: selectedLocation, open: inspectorOpen, selectTrack, selectLocation, changeWorkspace, closeLocation } = useMapInspector(overview, workspace, onWorkspace)
  useEffect(() => { onInspectorChange(inspectorOpen); return () => onInspectorChange(false) }, [inspectorOpen, onInspectorChange])
  const locations = useMemo(() => activeOnly ? overview.locations.filter(location => location.series.some(connection => connection.active)) : overview.locations, [activeOnly, overview.locations])
  const anchor = Math.floor(cursorMs / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS
  const profiles = useMemo(() => {
    if (!inspectorOpen) return null
    const profiles = projectTrafficProfiles(overview.scene, trafficIndex, anchor)
    return workspace.direction === 'both' ? profiles : new Map([...profiles].map(([id, profile]) => [id, { ...profile, rates: (workspace.direction === 'sent' ? profile.outRates : profile.inRates) ?? profile.rates.map(() => 0) }]))
  }, [inspectorOpen, overview.scene, trafficIndex, anchor, workspace.direction])
  const traffic = selected && profiles ? trackTraffic(selected, profiles) : null
  const locationTraffic = selectedLocation && profiles ? seriesTraffic(overview.tracks.flatMap(track => track.series), profiles) : null
  useEffect(() => {
    if (!workspace.expanded) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape' && !document.querySelector('dialog[open]') && !event.defaultPrevented) { onWorkspace({ ...workspace, expanded: false }); requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[aria-label="Expand traffic timeline"]')?.focus()) } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [workspace, onWorkspace])
  const quality = destinationLoading ? 'loading' : destinationError ? 'unavailable' : overview.total.partial ? 'partial' : 'captured'
  return <div className="atlas-composition" data-selected-track={selected?.id} data-inspector-open={inspectorOpen || undefined} data-track-count={overview.tracks.length} data-destination-count={locations.length} data-workspace={workspace.expanded ? 'timeline' : 'map'} data-location-filter={workspace.locationId ?? ''}>
    <div className="atlas-map-surface" hidden={workspace.expanded}>
      <EqualEarthMap controlsRef={controls} locations={locations} origin={scene.origin} direction={workspace.direction} selected={workspace.locationId} onSelect={selectLocation} labels={preferences.labels} showTraffic={showTraffic} />
      <div className="atlas-vignette" />
      <div className="atlas-map-heading"><MapIcon name="globe" size={15} /><span>NETWORK ATLAS</span><i /><span className="atlas-map-heading-detail">Equal Earth · {directionLabel(workspace.direction)}</span></div>
      <div className="atlas-view-options"><button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic(value => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button></div>
      {scene.endpoints.length === 0 && !refreshing && <div className="atlas-empty"><MapIcon name="globe" size={30} /><h2>{unavailable ? 'Session data unavailable' : loading ? 'Connecting to your session' : 'No mapped destinations yet'}</h2><p>{unavailable ? 'Check the gateway connection and try again.' : loading ? 'Loading the network view…' : 'Geolocated traffic will appear here as it is observed.'}</p></div>}
      <div className="atlas-map-footer"><div className="atlas-legend"><span className="atlas-down"><i className="atlas-direction-swatch" />↓ Downloaded · to your devices</span><span className="atlas-up"><i className="atlas-direction-swatch is-sent" />↑ Sent · from your devices</span>{locations.some(location => location.country) && <span><i className="atlas-country-swatch" />Country estimate</span>}</div><p className="atlas-column-scale" data-volume-source={quality}>Paired bars · shared linear scale · {directionLabel(workspace.direction)}{destinationLoading ? ' · Loading…' : destinationError ? ' · Capture unavailable' : overview.total.partial ? ' · Partial capture' : ''}</p><p>Direct connections · country anchors are approximate · Coarse IP locations</p></div>
    </div>
    <MapOverview capturedToMs={destinationIndex.toMs ?? cursorMs} refreshing={refreshing} data={overview} state={workspace} onChange={changeWorkspace} startMs={destinationIndex.fromMs ?? scene.startMs} cursorMs={cursorMs} loading={destinationLoading} error={destinationError} selectedTrack={selected?.id ?? null} onTrack={selectTrack} activeOnly={activeOnly} onActiveOnly={setActiveOnly} />
    {workspace.expanded && <MapTimeline live={live} following={following} onFollowLive={onFollowLive} detailIndex={timelineDetailIndex} refreshing={refreshing} data={overview} state={workspace} onChange={changeWorkspace} index={destinationIndex} startMs={destinationIndex.fromMs ?? scene.startMs} endMs={endMs} cursorMs={cursorMs} onSeek={onSeekTime} onTrack={selectTrack} loading={destinationLoading} error={destinationError} />}
    {!selected && selectedLocation && locationTraffic && <MapLocationInspector cursorMs={cursorMs} order={workspace.order} refreshing={refreshing} key={selectedLocation.id} location={selectedLocation} tracks={overview.tracks} direction={workspace.direction} traffic={locationTraffic} loading={destinationLoading} error={destinationError} trafficLoading={trafficLoading} onTrack={selectTrack} onClose={closeLocation} onFit={() => {
      controls.current?.fit([[scene.origin.longitude, scene.origin.latitude], ...selectedLocation.country ? countryFitPositions(selectedLocation.country) : selectedLocation.position ? [selectedLocation.position] : []])
      if (workspace.expanded) onWorkspace({ ...workspace, expanded: false })
    }} />}
    {selected && traffic && <MapTrackInspector cursorMs={cursorMs} order={workspace.order} refreshing={refreshing} key={selected.id} direction={workspace.direction} track={selected} traffic={traffic} locationLabel={selectedLocation?.label} onClose={() => selectTrack(null)} onFit={() => {
      controls.current?.fit([[scene.origin.longitude, scene.origin.latitude], ...locations.filter(location => location.series.some(connection => connection.trackId === selected.id)).flatMap(location => location.country ? countryFitPositions(location.country) : location.position ? [location.position] : [])])
      if (workspace.expanded) onWorkspace({ ...workspace, expanded: false })
    }} />}
  </div>
}
