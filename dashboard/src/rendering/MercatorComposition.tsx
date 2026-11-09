import type { MapProps } from 'react-map-gl/maplibre'
import { FlyToInterpolator, WebMercatorViewport } from '@deck.gl/core'
import type { Color, MapViewState, PickingInfo } from '@deck.gl/core'
import { ArcLayer, ColumnLayer, PathLayer, ScatterplotLayer, TextLayer } from '@deck.gl/layers'
import { AnimatedMercator } from './AnimatedMercator'
import type { MapRendererProps } from '../map/MapWorkspaceView'
import { createMapGeometryCache, sameTrafficArcGeometry } from '../map/mapGeometryCache'
import { lazy, Suspense, useImperativeHandle, useMemo, useState } from 'react'
import type { MapPoint, MapPosition } from '../map/mapModel'
import { projectMapFrame } from '../map/mapModel'
import { FlowArcLayer } from '../map/FlowArcLayer'
import { MapIcon } from '../map/MapIcon'
import { formatBytes } from '../map/format'
import type { BundledMapArc } from '../map/bundleMapArcs'
import { connectionHasTrack } from '../map/bundleMapArcs'
import { directionalVolumeArcs } from '../map/mapTraffic'
import type { TrafficArc } from '../map/mapTraffic'
import { trackOpacity } from '../map/mapTracks'
import { directionColor } from '../map/mapWorkspace'
import { CountryLabels } from '../map/CountryLabels'
import { CountryArcLayer, CountryFlowArcLayer, CountryFootprintLayer } from '../map/CountryLayers'
import { countryFitPositions, countryFootprint } from '../map/countryFootprints'
import { columnMetersPerPixel, projectDestinationVolumes, directionalColumns } from '../map/destinationVolumes'
import type { DestinationColumn, DestinationVolume, DirectionalColumn } from '../map/destinationVolumes'

const TiledBasemap = lazy(() => import('../map/TiledBasemap'))
function Basemap(props: MapProps) { return <Suspense fallback={null}><TiledBasemap {...props} /></Suspense> }

const TEAL: Color = [88, 222, 192, 235]
const GRATICULE: MapPosition[][] = [
  ...Array.from({ length: 13 }, (_, index) => [[-180 + index * 30, -80], [-180 + index * 30, 80]] as MapPosition[]),
  ...Array.from({ length: 5 }, (_, index) => Array.from({ length: 37 }, (_, x) => [-180 + x * 10, -60 + index * 30] as MapPosition)),
]

export function MercatorComposition({ controlsRef, inspection, profiles: trafficProfiles, trafficAnchorMs, emptyState, cursorMs, preferences, theme, workspace, overview, scene, clock, width: compositionWidth, height: compositionHeight, playbackEpochMs, mapStyleUrl, trafficLoading, destinationIndex, destinationLoading }: MapRendererProps) {
  const width = compositionWidth > 760 ? compositionWidth - 290 : compositionWidth
  const height = compositionWidth > 760 ? compositionHeight : Math.max(100, compositionHeight - 260)
  const mapFrame = useMemo(() => projectMapFrame(overview.scene, cursorMs), [cursorMs, overview.scene])
  const [viewState, setViewState] = useState<MapViewState>(() => ({
    longitude: scene.origin.longitude - (width > 760 ? 42 : 0), latitude: Math.max(-55, Math.min(55, scene.origin.latitude - 16)),
    zoom: width > 760 ? 1.55 : 1.4, minZoom: -1, maxZoom: 16, pitch: 35, bearing: 0,
  }))
  const [showTraffic, setShowTraffic] = useState(true)
  const [mapError, setMapError] = useState(false)
  const { track: selected, location: selectedLocation, open: inspectorOpen, selectLocation } = inspection
  const selection = selected?.id ?? null
  const visiblePoints = mapFrame.points
  const destinations = useMemo(() => destinationLoading ? [] : projectDestinationVolumes(overview.scene, overview.bySeries, destinationIndex, cursorMs, overview.volumeBySeries), [destinationLoading, overview.scene, overview.bySeries, destinationIndex, cursorMs, overview.volumeBySeries])
  const countryDestinations = useMemo(() => destinations.filter(destination => destination.country), [destinations])
  const countryVolumes = useMemo(() => new Map(countryDestinations.map(destination => [destination.country!.code, destination])), [countryDestinations])
  const cityPoints = useMemo(() => visiblePoints.filter(point => !point.country), [visiblePoints])
  // Geometry changes only with the country set, not on each animation frame.
  const countrySet = [...new Set(scene.endpoints.map(endpoint => countryFootprint(endpoint)?.code).filter(Boolean))].sort().join('|')
  const countryGeometry = useMemo(() => countrySet.split('|').flatMap(code => countryFootprint({ country: code, position: [0, 0] })?.polygons.map(polygon => ({ countryCode: code, polygon })) ?? []), [countrySet])
  const countryCodes = [...countryVolumes.keys()].sort().join('|')
  const countryPolygons = useMemo(() => countryGeometry.filter(polygon => countryCodes.split('|').includes(polygon.countryCode)), [countryGeometry, countryCodes])
  const countryBorders = useMemo(() => countryPolygons.flatMap(polygon => polygon.polygon.map(path => ({ countryCode: polygon.countryCode, path }))), [countryPolygons])
  const columns = useMemo(() => directionalColumns(destinations), [destinations])
  const columnLayers = useMemo(() => [
    { focused: false, data: selection ? columns.filter(column => column.trackId !== selection) : [] },
    { focused: true, data: selection ? columns.filter(column => column.trackId === selection) : columns },
  ], [selection, columns])
  const destinationLabels = useMemo(() => {
    const viewport = new WebMercatorViewport({ ...viewState, width, height })
    const occupied: number[][] = []
    return destinations.filter(destination => {
      if (destination.country) return false
      if (selection && !destination.tracks.some(track => track.trackId === selection)) return false
      const [x, y] = viewport.project([...destination.position, destination.height * columnMetersPerPixel(destination.position[1], viewState.zoom)])
      if (x < 35 || x > width - 55 || y < 90 || y > height - 90 || (x < 30)
        || (inspectorOpen && width > 1000 && x > width - 385) || occupied.some(([px, py]) => Math.abs(px - x) < 95 && Math.abs(py - y) < 42) || occupied.length >= 10) return false
      occupied.push([x, y])
      return true
    })
  }, [destinations, viewState, width, height, selection, inspectorOpen])
  const visibleArcs = mapFrame.arcs
  const geometry = useMemo(() => createMapGeometryCache(), [])
  const { connections, countryConnections } = useMemo(() => geometry(visibleArcs), [geometry, visibleArcs])
  const trafficArcs = useMemo(() => directionalVolumeArcs(connections, trafficProfiles), [connections, trafficProfiles])
  const countryTraffic = useMemo(() => directionalVolumeArcs(countryConnections, trafficProfiles), [countryConnections, trafficProfiles])
  const volumeLayers = useMemo(() => [
    { focused: false, data: trafficArcs.filter(arc => !connectionHasTrack(arc, selection)) },
    { focused: true, data: trafficArcs.filter(arc => connectionHasTrack(arc, selection)) },
  ], [selection, trafficArcs])
  const partialTraffic = Array.from(trafficProfiles.values()).some((profile) => profile.source === 'partial')
  const origin = useMemo(() => [{ position: [scene.origin.longitude, scene.origin.latitude] as MapPosition, label: scene.origin.label }], [scene.origin])

  const animation = useMemo(() => ({ clock, epochMs: playbackEpochMs, anchorMs: trafficAnchorMs }), [clock, playbackEpochMs, trafficAnchorMs])

  const layers = useMemo(() => {
    if (workspace.expanded) return []
    const connectionOpacity = (arc: BundledMapArc) => connectionHasTrack(arc, selection) ? 1 : 0.09
    const neutralColor = (): Color => theme === 'light' ? [83, 111, 117] : [143, 171, 180]
    const flowColor = (value?: number): Color => directionColor(value ?? 1, theme === 'light')
    const arcProps = {
      data: connections, greatCircle: true, wrapLongitude: true, numSegments: 160,
      getSourcePosition: (arc: BundledMapArc) => arc.sourcePosition,
      getTargetPosition: (arc: BundledMapArc) => arc.targetPosition,
      getHeight: 0.18, getTilt: 0,
      visible: showTraffic, parameters: { depthCompare: 'always' as const, depthWriteEnabled: false },
      updateTriggers: { getSourceColor: [selection, theme], getTargetColor: [selection, theme] },
    }
    const volumeProps = {
      dataComparator: sameTrafficArcGeometry,
      updateTriggers: { ...arcProps.updateTriggers, getRadii0: [trafficProfiles], getRadii1: [trafficProfiles], getRadii2: [trafficProfiles] },
    }
    const countryColor = (code: string): Color => {
      const destination = countryVolumes.get(code)
      return selection && destination?.tracks.some(track => track.trackId === selection) ? neutralColor() : TEAL
    }
    const countryOpacity = (code: string) => !selection || countryVolumes.get(code)?.tracks.some(track => track.trackId === selection) ? 1 : 0.12
    return [
      new CountryFootprintLayer({
        id: 'country-footprints', data: countryPolygons, getPolygon: shape => shape.polygon, pickable: true,
        getFillColor: shape => alpha(countryColor(shape.countryCode), (0.16 + Math.min(0.2, Math.log2(1 + (countryVolumes.get(shape.countryCode)?.bytes ?? 0) / 4096) * 0.015)) * countryOpacity(shape.countryCode)),
        updateTriggers: { getFillColor: [selection, countryVolumes, theme] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new PathLayer({
        id: 'country-outlines', data: countryBorders, getPath: border => border.path, getWidth: 1, widthUnits: 'pixels',
        getColor: border => alpha(countryColor(border.countryCode), 0.55 * countryOpacity(border.countryCode)),
        updateTriggers: { getColor: [selection, countryVolumes, theme] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new CountryArcLayer<BundledMapArc>({
        ...arcProps, id: 'country-connections', data: countryConnections, getWidth: 1.5,
        getSourceColor: arc => alpha(neutralColor(), 0.5 * connectionOpacity(arc)),
        getTargetColor: arc => alpha(neutralColor(), 0.4 * connectionOpacity(arc)),
      }),
      new CountryFlowArcLayer<TrafficArc>({
        ...arcProps, ...volumeProps, id: 'country-traffic', data: countryTraffic, animation,
        getRadii0: arc => arc.radii.slice(0, 4), getRadii1: arc => arc.radii.slice(4, 8), getRadii2: arc => arc.radii.slice(8, 12),
        getDirection: arc => arc.direction ?? 1,
        getSourceColor: arc => alpha(flowColor(arc.direction), connectionOpacity(arc)),
        getTargetColor: arc => alpha(flowColor(arc.direction), connectionOpacity(arc)),
      }),
      new PathLayer<MapPosition[]>({
        id: 'atlas-grid', data: GRATICULE, getPath: (path) => path,
        getColor: [69, 102, 118, 27], getWidth: 1, widthUnits: 'pixels', pickable: false,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, id: 'connection-glow',
        getSourceColor: (arc) => alpha(neutralColor(), 0.06 * connectionOpacity(arc)),
        getTargetColor: (arc) => alpha(neutralColor(), 0.04 * connectionOpacity(arc)), getWidth: 3,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, id: 'connection-strips', getWidth: 1,
        getSourceColor: (arc) => alpha(neutralColor(), 0.44 * connectionOpacity(arc)),
        getTargetColor: (arc) => alpha(neutralColor(), 0.34 * connectionOpacity(arc)),
      }),
      ...volumeLayers.map(({ focused, data }) => new FlowArcLayer<TrafficArc>({
        ...arcProps, ...volumeProps, data, id: focused ? 'traffic-streams' : 'muted-traffic-streams', animation,
        getRadii0: (arc) => arc.radii.slice(0, 4), getRadii1: (arc) => arc.radii.slice(4, 8), getRadii2: (arc) => arc.radii.slice(8, 12),
        getDirection: arc => arc.direction ?? 1,
        getSourceColor: (arc) => alpha(flowColor(arc.direction), connectionOpacity(arc)),
        getTargetColor: (arc) => alpha(flowColor(arc.direction), 0.92 * connectionOpacity(arc)),
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused },
      })),
      new ScatterplotLayer<MapPoint>({
        id: 'destination-halos', data: cityPoints, getPosition: (point) => point.position,
        radiusUnits: 'pixels', getRadius: (point) => point.trackId === selection ? 17 : 10,
        getFillColor: (point) => alpha(neutralColor(), (point.activeSeriesCount > 0 ? 0.08 : 0.04) * trackOpacity(point.trackId, selection)),
        updateTriggers: { getRadius: selection, getFillColor: [selection, theme] }, parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destinations', data: cityPoints, pickable: true, radiusUnits: 'pixels', stroked: true,
        getPosition: (point) => point.position, getRadius: (point) => point.trackId === selection ? 5.5 : 3.5,
        getFillColor: (point) => alpha(neutralColor(), (point.activeSeriesCount > 0 ? 1 : 0.55) * trackOpacity(point.trackId, selection)),
        getLineColor: (point) => point.trackId === selection ? [230, 255, 248, 255] : [11, 24, 34, 230 * trackOpacity(point.trackId, selection)],
        getLineWidth: 1.5, lineWidthUnits: 'pixels',
        updateTriggers: { getRadius: selection, getFillColor: [selection, theme], getLineColor: [selection, theme] }, parameters: { depthCompare: 'always' },
      }),
      ...columnLayers.map(({ focused, data }) => new ColumnLayer<DirectionalColumn>({
        id: focused ? 'destination-columns' : 'muted-destination-columns', data, pickable: true,
        diskResolution: 6, radius: 6, radiusUnits: 'pixels', angle: 30, extruded: true, flatShading: true,
        getPosition: column => [column.destination.position[0] + column.direction * 7 * 360 / (512 * 2 ** viewState.zoom), column.destination.position[1], column.base * columnMetersPerPixel(column.destination.position[1], viewState.zoom)],
        getElevation: column => column.height * columnMetersPerPixel(column.destination.position[1], viewState.zoom),
        getFillColor: column => alpha(flowColor(column.direction), 0.92 * trackOpacity(column.trackId, selection)),
        material: { ambient: 0.38, diffuse: 0.7, shininess: 45, specularColor: [130, 170, 180] },
        updateTriggers: { getPosition: viewState.zoom, getElevation: viewState.zoom, getFillColor: [selection, theme] },
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused },
      })),
      new TextLayer<DestinationVolume>({
        id: 'destination-totals', data: destinationLabels,
        getPosition: destination => [...destination.position, destination.height * columnMetersPerPixel(destination.position[1], viewState.zoom)],
        getText: destination => `${''}${formatBytes(destination.received + destination.sent)}`,
        visible: preferences.labels,
        characterSet: '0123456789. BkMGT≈↓↑',
        getSize: 11, getPixelOffset: [0, -14], fontFamily: 'system-ui, sans-serif', fontWeight: 600,
        getColor: [223, 240, 239, 255], background: true, getBackgroundColor: [10, 23, 32, 225], backgroundPadding: [6, 4],
        updateTriggers: { getPosition: viewState.zoom }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new ScatterplotLayer({
        id: 'gateway-ring', data: origin, getPosition: (point) => point.position,
        radiusUnits: 'pixels', getRadius: 13, stroked: true, filled: true,
        getFillColor: [88, 222, 192, 20], getLineColor: [88, 222, 192, 120], getLineWidth: 1,
        lineWidthUnits: 'pixels', parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer({
        id: 'gateway-core', data: origin, getPosition: (point) => point.position,
        radiusUnits: 'pixels', getRadius: 5, stroked: true,
        getFillColor: [208, 255, 242, 255], getLineColor: TEAL, getLineWidth: 2,
        lineWidthUnits: 'pixels', parameters: { depthCompare: 'always' },
      }),
      new TextLayer({
        id: 'gateway-label', visible: preferences.labels, data: origin, getPosition: (point) => point.position,
        getText: () => 'GATEWAY', getSize: 10, getColor: [175, 218, 209, 255],
        getPixelOffset: [0, 26], fontFamily: 'system-ui, sans-serif', fontWeight: 600,
        background: true, getBackgroundColor: [10, 23, 32, 230], backgroundPadding: [7, 4],
        getTextAnchor: 'middle', getAlignmentBaseline: 'center', parameters: { depthCompare: 'always' },
      }),
    ].filter(layer => layer.props.visible !== false && (!Array.isArray(layer.props.data) || layer.props.data.length > 0))
  }, [animation, trafficProfiles, connections, origin, selection, showTraffic, viewState.zoom, volumeLayers, columnLayers, destinationLabels, countryPolygons, countryBorders, countryVolumes, countryConnections, countryTraffic, cityPoints, theme, workspace.expanded, preferences.labels])

  function moveTo(next: Partial<MapViewState>) {
    setViewState((current) => ({ ...current, ...next, transitionDuration: 700, transitionInterpolator: new FlyToInterpolator() }))
  }

  function fitNetwork(trackId?: string) {
    const positions = [origin[0].position, ...visiblePoints.filter(point => !trackId || point.trackId === trackId).flatMap(point => 'country' in point && point.country ? countryFitPositions(point.country) : [point.position])]
    // Unwrap around the gateway so dateline connections take the short way around.
    const longitudes = positions.map(([lon]) => scene.origin.longitude + ((lon - scene.origin.longitude + 540) % 360) - 180)
    const latitudes = positions.map(([, lat]) => Math.max(-80, Math.min(80, lat)))
    const padding = compositionWidth > 760 ? { left: 45, right: inspectorOpen && compositionWidth > 1000 ? 350 : 60, top: 100, bottom: 100 } : { left: 50, right: 50, top: 75, bottom: 220 }
    const viewport = new WebMercatorViewport({ width, height }).fitBounds([
      [Math.min(...longitudes), Math.min(...latitudes)], [Math.max(...longitudes), Math.max(...latitudes)],
    ], { padding, maxZoom: 6 })
    // fitBounds is planar. Leave room for the tops of columns in perspective too.
    const fittedDestinations = destinations.filter(destination => !trackId || destination.tracks.some(track => track.trackId === trackId))
    let zoom = viewport.zoom
    for (let attempt = 0; attempt < 40 && zoom > -1; attempt += 1) {
      const camera = new WebMercatorViewport({ width, height, longitude: viewport.longitude, latitude: viewport.latitude, zoom, pitch: viewState.pitch, bearing: 0 })
      const tops = fittedDestinations.map(destination => [
        scene.origin.longitude + ((destination.position[0] - scene.origin.longitude + 540) % 360) - 180,
        destination.position[1], destination.height * columnMetersPerPixel(destination.position[1], zoom),
      ])
      const projected = [...longitudes.map((lon, i) => [lon, latitudes[i]]), ...tops].map(position => camera.project(position))
      if (projected.every(([x, y]) => x >= padding.left && x <= width - padding.right && y >= padding.top && y <= height - padding.bottom)) break
      zoom = Math.max(-1, zoom - 0.1)
    }
    moveTo({ longitude: viewport.longitude, latitude: viewport.latitude, zoom, bearing: 0 })
  }

  useImperativeHandle(controlsRef, () => ({ fit: fitNetwork }))

  return (
    <div className="atlas-map-surface" hidden={workspace.expanded} data-map-zoom={viewState.zoom.toFixed(2)} data-map-pitch={viewState.pitch} data-connection-count={connections.length + countryConnections.length} data-city-column-count={columns.length}>
      <AnimatedMercator clock={clock} active={!workspace.expanded && showTraffic && (trafficArcs.length + countryTraffic.length > 0)} useDevicePixels deviceProps={{ webgl: { antialias: false, preserveDrawingBuffer: false, powerPreference: 'high-performance' } }}
        controller={{ dragRotate: true, touchRotate: true }} viewState={viewState}
        onViewStateChange={({ viewState: next }) => setViewState(next as MapViewState)}
        layers={layers} getTooltip={info => {
          if (info.layer?.id === 'country-footprints' && info.object) {
            const destination = countryVolumes.get(info.object.countryCode)
            return destination ? { text: `${destination.location} · Country estimate\nCity unknown\n${formatBytes(destination.received + destination.sent)} downloaded + sent\nClick for country totals and tracks` } : null
          }
          return tooltipForPoint(info)
        }}
        onClick={({ object, layer }) => {
          if (layer?.id === 'country-footprints' && object) { const id = countryVolumes.get(object.countryCode)?.id ?? null; selectLocation(selectedLocation?.id === id ? null : id); return }
          if (!object) return
          if (['destinations', 'destination-columns', 'muted-destination-columns'].includes(layer?.id ?? '')) {
            const locationId = 'destination' in object ? (object as DestinationColumn).destination.id : (object as MapPoint).position.join(',')
            selectLocation(selectedLocation?.id === locationId ? null : locationId)
          } }}
        getCursor={({ isDragging, isHovering }) => isDragging ? 'grabbing' : isHovering ? 'pointer' : 'grab'}
      >
        <Basemap mapStyle={mapStyleUrl} minZoom={-1} attributionControl={{ compact: true }}
          onError={() => setMapError(true)} onIdle={() => setMapError(false)} />
      </AnimatedMercator>
      {preferences.labels && <CountryLabels destinations={countryDestinations} viewState={viewState} width={width} height={height} selection={selection} selectedLocationId={selectedLocation?.id ?? null} inspectorOpen={inspectorOpen} onCountry={selectLocation} />}
      <div className="atlas-vignette" />

      <div className="atlas-map-heading"><span>NETWORK ATLAS</span><span className="atlas-map-heading-detail">Mercator</span></div>
      <div className="atlas-view-options">
        <div className="atlas-segmented atlas-view-switch" aria-label="Map perspective">
          <button type="button" aria-pressed={viewState.pitch !== 0} onClick={() => moveTo({ pitch: 35 })}>Perspective</button>
          <button type="button" aria-pressed={viewState.pitch === 0} onClick={() => moveTo({ pitch: 0, bearing: 0 })}>Top-down</button>
        </div>
        <button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic((value) => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button>
      </div>


      {emptyState}
      {mapError && <div className="atlas-map-error" role="status">Basemap tiles are unavailable. Traffic is still shown.</div>}

      <div className="atlas-map-tools" aria-label="Map controls">
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.min(16, viewState.zoom + 1) })} aria-label="Zoom in" title="Zoom in"><MapIcon name="plus" /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.max(-1, viewState.zoom - 1) })} aria-label="Zoom out" title="Zoom out"><MapIcon name="minus" /></button>
        <span />
        <button type="button" className="atlas-icon-button" onClick={() => fitNetwork()} aria-label="Fit network" title="Fit network"><MapIcon name="expand" size={17} /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ longitude: scene.origin.longitude, latitude: scene.origin.latitude, zoom: 5, bearing: 0 })} aria-label="Center on gateway" title="Center on gateway"><MapIcon name="target" /></button>
      </div>
      <div className="atlas-map-footer"><div className="atlas-legend"><span className="atlas-down"><i className="atlas-direction-swatch" />↓ Downloaded · to your devices</span><span className="atlas-up"><i className="atlas-direction-swatch is-sent" />↑ Sent · from your devices</span>{countryDestinations.length > 0 && <span><i className="atlas-country-swatch" />Country estimate</span>}</div><p>Direct connections · Coarse IP locations{(trafficLoading || partialTraffic) ? trafficLoading ? ' · Loading rates' : ' · Partial rates' : ''}</p></div>
      </div>

  )
}

function alpha(color: Color, opacity: number): Color {
  return [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)]
}

function tooltipForPoint({ object, layer }: PickingInfo<MapPoint | DestinationColumn>) {
  if (!object || !['destinations', 'destination-columns', 'muted-destination-columns'].includes(layer?.id ?? '')) return null
  const destination = 'destination' in object ? object.destination : null
  const lines = 'destination' in object && destination
    ? [destination.location, `${formatBytes(destination.received + destination.sent)} downloaded + sent`,
      `↓ ${formatBytes(destination.received)} downloaded from this location`, `↑ ${formatBytes(destination.sent)} sent to this location`,
      `${destination.ips.length} ${destination.ips.length === 1 ? 'destination' : 'destinations'} · ${destination.seriesCount} series`,
      `${object.label} · ${formatBytes(object.bytes)} of total`,
      `Captured wire bytes · completed sample bins${destination.partial ? ' · Partial capture' : ''}`,
      'Click to inspect this location']
    : 'ip' in object ? [object.label, object.location, object.ip, `${object.seriesCount.toLocaleString()} traffic series`, 'Click to inspect this location'] : []
  return {
    text: lines.filter(Boolean).join('\n'),
    style: { backgroundColor: '#11232e', color: '#e1eeed', fontSize: '12px', lineHeight: '1.7', border: '1px solid #30464f', borderRadius: '8px', padding: '12px 16px' },
  }
}
