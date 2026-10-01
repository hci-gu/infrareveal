import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { AbsoluteFill } from 'remotion'
import type { MapCompositionProps } from './MapComposition'
import { EqualEarthMap } from '../map/EqualEarthMap'
import type { EqualEarthControls } from '../map/EqualEarthMap'
import { MapOverview } from '../map/MapOverview'
import { MapTimeline } from '../map/MapTimeline'
import { MapTrackInspector } from '../map/MapTrackInspector'
import { MapIcon } from '../map/MapIcon'
import { directionLabel } from '../map/mapWorkspace'
import { countryFitPositions } from '../map/countryFootprints'
import { projectTrafficProfiles, TRAFFIC_BUCKET_MS } from '../map/mapTraffic'
import { trackTraffic } from '../map/mapTracks'

/** Equal Earth needs locations and totals, never a Mercator scene or tube geometry. */
export function EqualEarthComposition({ preferences, workspace, overview, onWorkspace, onSeekTime, cursorMs, endMs, scene, trackCatalog, unavailable, loading, trafficIndex, destinationIndex, destinationLoading, destinationError }: MapCompositionProps) {
  const controls = useRef<EqualEarthControls>(null)
  const [activeOnly, setActiveOnly] = useState(false)
  const [showTraffic, setShowTraffic] = useState(true)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const selected = overview.tracks.find(track => track.id === selectedId)
  const selectTrack = useCallback((id: string | null) => {
    setSelectedId(id)
    if (!id) requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(`button[data-track-id="${CSS.escape(selectedId ?? '')}"]`)?.focus({ preventScroll: true }))
  }, [selectedId])
  const selectLocation = useCallback((locationId: string | null) => onWorkspace({ ...workspace, locationId }), [workspace, onWorkspace])
  const locations = useMemo(() => activeOnly ? overview.locations.filter(location => location.connections.some(connection => connection.active)) : overview.locations, [activeOnly, overview.locations])
  const anchor = Math.floor(cursorMs / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS
  const profiles = useMemo(() => {
    if (!selected) return null
    const profiles = projectTrafficProfiles(overview.scene, trafficIndex, anchor)
    return workspace.direction === 'both' ? profiles : new Map([...profiles].map(([id, profile]) => [id, { ...profile, rates: (workspace.direction === 'sent' ? profile.outRates : profile.inRates) ?? profile.rates.map(() => 0) }]))
  }, [selected, overview.scene, trafficIndex, anchor, workspace.direction])
  const traffic = selected && profiles ? trackTraffic(selected, overview.scene, profiles) : null
  useEffect(() => {
    if (!workspace.expanded) return
    const onKey = (event: KeyboardEvent) => { if (event.key === 'Escape' && !document.querySelector('dialog[open]') && !event.defaultPrevented) { onWorkspace({ ...workspace, expanded: false }); requestAnimationFrame(() => document.querySelector<HTMLButtonElement>('[aria-label="Expand traffic timeline"]')?.focus()) } }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [workspace, onWorkspace])
  const quality = destinationLoading ? 'loading' : destinationError ? 'unavailable' : overview.total.estimated ? 'estimated' : overview.total.partial ? 'partial' : 'captured'
  return <AbsoluteFill className="atlas-composition" data-selected-track={selected?.id} data-track-count={overview.tracks.length} data-destination-count={locations.length} data-workspace={workspace.expanded ? 'timeline' : 'map'} data-location-filter={workspace.locationId ?? ''}>
    <div className="atlas-map-surface" hidden={workspace.expanded}>
      <EqualEarthMap controlsRef={controls} locations={locations} origin={scene.origin} direction={workspace.direction} selected={workspace.locationId} onSelect={selectLocation} labels={preferences.labels} showTraffic={showTraffic} />
      <div className="atlas-vignette" />
      <div className="atlas-map-heading"><MapIcon name="globe" size={15} /><span>NETWORK ATLAS</span><i /><span className="atlas-map-heading-detail">Equal Earth · {directionLabel(workspace.direction)}</span></div>
      <div className="atlas-view-options"><button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic(value => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button></div>
      {scene.endpoints.length === 0 && <div className="atlas-empty"><MapIcon name="globe" size={30} /><h2>{unavailable ? 'Session data unavailable' : loading ? 'Connecting to your session' : 'No mapped destinations yet'}</h2><p>{unavailable ? 'Check the gateway connection and try again.' : loading ? 'Loading the network view…' : 'Geolocated traffic will appear here as it is observed.'}</p></div>}
      <div className="atlas-map-footer"><div className="atlas-legend"><span className="atlas-down"><i className="atlas-direction-swatch" />↓ Downloaded · to your devices</span><span className="atlas-up"><i className="atlas-direction-swatch is-sent" />↑ Sent · from your devices</span>{locations.some(location => location.country) && <span><i className="atlas-country-swatch" />Country estimate</span>}</div><p className="atlas-column-scale" data-volume-source={quality}>Paired bars · shared linear scale · {directionLabel(workspace.direction)}{destinationLoading ? ' · Loading…' : destinationError ? ' · Capture unavailable' : overview.total.estimated ? ' · ≈ Includes estimates' : overview.total.partial ? ' · Partial capture' : ''}</p><p>Simplified connections · country anchors are approximate · Coarse IP locations</p></div>
    </div>
    <MapOverview data={overview} state={workspace} onChange={onWorkspace} startMs={scene.startMs} cursorMs={cursorMs} loading={destinationLoading} error={destinationError} selectedTrack={selected?.id ?? null} onTrack={selectTrack} activeOnly={activeOnly} onActiveOnly={setActiveOnly} />
    {workspace.expanded && <MapTimeline data={overview} state={workspace} onChange={onWorkspace} index={destinationIndex} startMs={scene.startMs} endMs={endMs} cursorMs={cursorMs} onSeek={onSeekTime} onTrack={selectTrack} loading={destinationLoading} error={destinationError} />}
    {selected && traffic && <MapTrackInspector key={selected.id} direction={workspace.direction} track={selected} catalog={trackCatalog} cursorMs={cursorMs} traffic={traffic} onClose={() => selectTrack(null)} onFit={() => {
      controls.current?.fit([[scene.origin.longitude, scene.origin.latitude], ...locations.filter(location => location.connections.some(connection => connection.id === selected.id)).flatMap(location => location.country ? countryFitPositions(location.country) : location.position ? [location.position] : [])])
      if (workspace.expanded) onWorkspace({ ...workspace, expanded: false })
    }} />}
  </AbsoluteFill>
}
