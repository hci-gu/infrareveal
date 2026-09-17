import { FlyToInterpolator, WebMercatorViewport } from '@deck.gl/core'
import type { Color, MapViewState, PickingInfo } from '@deck.gl/core'
import { ArcLayer, ColumnLayer, PathLayer, ScatterplotLayer, TextLayer } from '@deck.gl/layers'
import DeckGL from '@deck.gl/react'
import type { StyleSpecification } from 'maplibre-gl'
import { useEffect, useMemo, useState } from 'react'
import MapLibre from 'react-map-gl/maplibre'
import { AbsoluteFill, useCurrentFrame, useVideoConfig } from 'remotion'
import { timeForFrame } from '@infrareveal/session-state'
import type { MapHopPoint, MapPoint, MapPosition, MapTimelineScene } from '../map/mapModel'
import { projectMapFrame } from '../map/mapModel'
import { FlowArcLayer } from '../map/FlowArcLayer'
import { FlowPathLayer } from '../map/FlowPathLayer'
import { buildTrafficPaths, trafficPathEdges, trafficPathStrips } from '../map/trafficPaths'
import type { TrafficPathEdge, TrafficPathStrip } from '../map/trafficPaths'
import { GapArcLayer } from '../map/GapArcLayer'
import { MapIcon } from '../map/MapIcon'
import { formatBytes } from '../map/format'
import { bundleMapArcs } from '../map/bundleMapArcs'
import type { BundledMapArc } from '../map/bundleMapArcs'
import { projectTrafficProfiles, TRAFFIC_BUCKET_MS, directionalVolumeArcs } from '../map/mapTraffic'
import type { MapTrafficIndex, TrafficArc } from '../map/mapTraffic'
import { projectMapTracks, sceneForTracks, trackOpacity, trackTraffic } from '../map/mapTracks'
import type { MapTrackCatalog } from '../map/mapTracks'
import { MapTrackList } from '../map/MapTrackList'
import { MapTrackInspector } from '../map/MapTrackInspector'
import { CountryLabels } from '../map/CountryLabels'
import { CountryArcLayer, CountryFlowArcLayer, CountryFootprintLayer } from '../map/CountryLayers'
import { countryFitPositions, countryFootprint } from '../map/countryFootprints'
import { columnMetersPerPixel, projectDestinationVolumes } from '../map/destinationVolumes'
import type { DestinationColumn, DestinationVolume, DestinationVolumeIndex } from '../map/destinationVolumes'

export type MapCompositionProps = {
  scene: MapTimelineScene
  trackCatalog: MapTrackCatalog
  fps: number
  mapStyleUrl: string | StyleSpecification
  unavailable: boolean
  loading: boolean
  trafficIndex: MapTrafficIndex
  trafficLoading: boolean
  destinationIndex: DestinationVolumeIndex
  destinationLoading: boolean
  destinationError: boolean
}

const MAP_PROJECTION_INTERVAL_MS = 250
const TEAL: Color = [88, 222, 192, 235]
const GRATICULE: MapPosition[][] = [
  ...Array.from({ length: 13 }, (_, index) => [[-180 + index * 30, -80], [-180 + index * 30, 80]] as MapPosition[]),
  ...Array.from({ length: 5 }, (_, index) => Array.from({ length: 37 }, (_, x) => [-180 + x * 10, -60 + index * 30] as MapPosition)),
]

export function MapComposition({ scene, trackCatalog, fps, mapStyleUrl, unavailable, loading, trafficIndex, trafficLoading, destinationIndex, destinationLoading, destinationError }: MapCompositionProps) {
  const frame = useCurrentFrame()
  const { width, height } = useVideoConfig()
  const cursorMs = timeForFrame(scene.startMs, frame, fps)
  const projectedCursorMs = Math.floor(cursorMs / MAP_PROJECTION_INTERVAL_MS) * MAP_PROJECTION_INTERVAL_MS
  const [showRoutes, setShowRoutes] = useState(true)
  const trackFrame = useMemo(() => projectMapTracks(trackCatalog, scene, projectedCursorMs), [trackCatalog, scene, projectedCursorMs])
  const trackScene = useMemo(() => sceneForTracks(scene, trackFrame.byFlow), [scene, trackFrame.byFlow])
  const displayScene = useMemo(() => showRoutes ? trackScene : {
    ...trackScene, endpoints: trackScene.endpoints.map(endpoint => ({ ...endpoint, routes: [] })),
  }, [showRoutes, trackScene])
  const mapFrame = useMemo(() => projectMapFrame(displayScene, projectedCursorMs), [projectedCursorMs, displayScene])
  const [viewState, setViewState] = useState<MapViewState>(() => ({
    longitude: scene.origin.longitude - (width > 760 ? 42 : 0), latitude: Math.max(-55, Math.min(55, scene.origin.latitude - 16)),
    zoom: width > 760 ? 1.55 : 1.4, minZoom: -1, maxZoom: 16, pitch: 35, bearing: 0,
  }))
  const [selectedCountry, setSelectedCountry] = useState<string | null>(null)
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeOnly, setActiveOnly] = useState(false)
  const [showTraffic, setShowTraffic] = useState(true)
  const [reducedMotion, setReducedMotion] = useState(false)
  const [mapError, setMapError] = useState(false)
  const selected = trackFrame.tracks.find(track => track.id === selectedId)
  const selection = selected ? selectedId : null
  const visiblePoints = useMemo(() => activeOnly ? mapFrame.points.filter((point) => point.activeFlowCount > 0) : mapFrame.points, [activeOnly, mapFrame.points])
  const visibleIPs = useMemo(() => activeOnly ? new Set(visiblePoints.map(point => point.ip)) : undefined, [activeOnly, visiblePoints])
  const destinations = useMemo(() => destinationLoading ? [] : projectDestinationVolumes(scene, trackFrame.byFlow, destinationIndex, cursorMs, visibleIPs), [destinationLoading, scene, trackFrame.byFlow, destinationIndex, cursorMs, visibleIPs])
  const countryDestinations = useMemo(() => destinations.filter(destination => destination.country), [destinations])
  const countryVolumes = useMemo(() => new Map(countryDestinations.map(destination => [destination.country!.code, destination])), [countryDestinations])
  const cityPoints = useMemo(() => visiblePoints.filter(point => !point.country), [visiblePoints])
  // Geometry changes only with the country set, not on each animation frame.
  const countryGeometry = useMemo(() => [...new Map(scene.endpoints.map(endpoint => countryFootprint(endpoint)).filter(country => country !== null).map(country => [country.code, country])).values()].flatMap(country => country.polygons.map(polygon => ({ countryCode: country.code, polygon }))), [scene])
  const countryCodes = [...countryVolumes.keys()].sort().join('|')
  const countryPolygons = useMemo(() => countryGeometry.filter(polygon => countryCodes.split('|').includes(polygon.countryCode)), [countryGeometry, countryCodes])
  const countryBorders = useMemo(() => countryPolygons.flatMap(polygon => polygon.polygon.map(path => ({ countryCode: polygon.countryCode, path }))), [countryPolygons])
  const columns = useMemo(() => destinations.filter(destination => !destination.country).flatMap(destination => destination.tracks), [destinations])
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
      if (x < 35 || x > width - 55 || y < 90 || y > height - 90 || (width > 760 && x < 330 && y < height - 130)
        || (selection && width > 1000 && x > width - 385) || occupied.some(([px, py]) => Math.abs(px - x) < 95 && Math.abs(py - y) < 42) || occupied.length >= 10) return false
      occupied.push([x, y])
      return true
    })
  }, [destinations, viewState, width, height, selection])
  const destinationEstimated = destinations.some(destination => destination.estimated)
  const destinationPartial = destinations.some(destination => destination.partial)
  const visibleArcs = useMemo(() => activeOnly ? mapFrame.arcs.filter(arc => arc.activeFlowCount > 0) : mapFrame.arcs, [activeOnly, mapFrame.arcs])
  // A traced connection belongs exclusively to its itinerary, never to the direct-arc renderer.
  const routes = useMemo(() => bundleMapArcs(visibleArcs.filter(arc => !arc.routeId && !arc.country)), [visibleArcs])
  const countryRoutes = useMemo(() => bundleMapArcs(visibleArcs.filter(arc => arc.country)), [visibleArcs])
  const tracedPaths = useMemo(() => buildTrafficPaths(visibleArcs.filter(arc => !arc.country)), [visibleArcs])
  const tracedStrips = useMemo(() => trafficPathStrips(tracedPaths), [tracedPaths])
  const measuredSpans = useMemo(() => routes.filter(arc => !showRoutes || !arc.gap), [routes, showRoutes])
  const unknownSpans = useMemo(() => showRoutes ? routes.filter(arc => arc.gap) : [], [routes, showRoutes])
  const hasUnknownSpans = unknownSpans.length > 0 || tracedPaths.some(path => path.gaps.some(Boolean))
  const visibleHops = useMemo(() => {
    const routeIds = new Set(visibleArcs.map(arc => `${arc.trackId}:${arc.routeId}`))
    const located = mapFrame.hops.filter(hop => routeIds.has(`${hop.trackId}:${hop.routeId}`))
    return [...new Map(located.map(hop => [`${hop.trackId}/${hop.address}/${hop.position.join(',')}`, hop])).values()]
  }, [mapFrame.hops, visibleArcs])
  const trafficAnchorMs = Math.floor(cursorMs / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS
  const trafficProfiles = useMemo(() => projectTrafficProfiles(trackScene, trafficIndex, trafficAnchorMs), [trackScene, trafficIndex, trafficAnchorMs])
  const trafficArcs = useMemo(() => directionalVolumeArcs(routes, trafficProfiles), [routes, trafficProfiles])
  const countryTraffic = useMemo(() => directionalVolumeArcs(countryRoutes, trafficProfiles), [countryRoutes, trafficProfiles])
  const tracedTraffic = useMemo(() => trafficPathEdges(directionalVolumeArcs(tracedPaths, trafficProfiles)), [tracedPaths, trafficProfiles])
  const volumeLayers = useMemo(() => [
    { focused: false, data: selection ? trafficArcs.filter(arc => arc.trackId !== selection) : [] },
    { focused: true, data: selection ? trafficArcs.filter(arc => arc.trackId === selection) : trafficArcs },
  ], [selection, trafficArcs])
  const pathVolumeLayers = useMemo(() => [
    { focused: false, data: selection ? tracedTraffic.filter(edge => edge.trackId !== selection) : [] },
    { focused: true, data: selection ? tracedTraffic.filter(edge => edge.trackId === selection) : tracedTraffic },
  ], [selection, tracedTraffic])
  const estimatedTraffic = Array.from(trafficProfiles.values()).some((profile) => profile.source === 'estimated')
  const partialTraffic = Array.from(trafficProfiles.values()).some((profile) => profile.source === 'partial')
  const selectedTraffic = selected ? trackTraffic(selected, trackScene, trafficProfiles) : null
  const origin = useMemo(() => [{ position: [scene.origin.longitude, scene.origin.latitude] as MapPosition, label: scene.origin.label }], [scene.origin])
  const countries = useMemo(() => new Set(trackScene.endpoints.filter(endpoint => endpoint.availableFromMs <= projectedCursorMs).map(endpoint => endpoint.country).filter(Boolean)).size, [trackScene, projectedCursorMs])
  const [volumeValue, volumeUnit] = formatBytes(trackFrame.tracks.reduce((sum, track) => sum + track.bytes, 0)).split(' ')
  const activeFlowCount = trackFrame.tracks.reduce((sum, track) => sum + track.activeCount, 0)
  function selectTrack(id: string | null) {
    setSelectedId(id)
    if (!id) requestAnimationFrame(() => document.querySelector<HTMLButtonElement>(`button[data-track-id="${CSS.escape(selectedId ?? '')}"]`)?.focus({ preventScroll: true }))
  }

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReducedMotion(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  const layers = useMemo(() => {
    const routeOpacity = (arc: BundledMapArc) => trackOpacity(arc.trackId, selection)
    const trackColor = (id: string | undefined): Color => id ? trackCatalog.colors.get(id) : TEAL
    const arcProps = {
      data: routes, greatCircle: true, wrapLongitude: true, numSegments: 160,
      getSourcePosition: (arc: BundledMapArc) => arc.sourcePosition,
      getTargetPosition: (arc: BundledMapArc) => arc.targetPosition,
      getHeight: (arc: BundledMapArc) => arc.height, getTilt: (arc: BundledMapArc) => arc.tilt,
      visible: showTraffic, parameters: { depthCompare: 'always' as const, depthWriteEnabled: false },
      updateTriggers: { getSourceColor: selection, getTargetColor: selection },
    }
    const countryColor = (code: string): Color => {
      const destination = countryVolumes.get(code)
      return selection && destination?.tracks.some(track => track.trackId === selection) ? trackColor(selection) : TEAL
    }
    const countryOpacity = (code: string) => !selection || countryVolumes.get(code)?.tracks.some(track => track.trackId === selection) ? 1 : 0.12
    return [
      new CountryFootprintLayer({
        id: 'country-footprints', data: countryPolygons, getPolygon: shape => shape.polygon, pickable: true,
        getFillColor: shape => alpha(countryColor(shape.countryCode), (0.16 + Math.min(0.2, Math.log2(1 + (countryVolumes.get(shape.countryCode)?.bytes ?? 0) / 4096) * 0.015)) * countryOpacity(shape.countryCode)),
        updateTriggers: { getFillColor: [selection, countryVolumes] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new PathLayer({
        id: 'country-outlines', data: countryBorders, getPath: border => border.path, getWidth: 1, widthUnits: 'pixels',
        getColor: border => alpha(countryColor(border.countryCode), 0.55 * countryOpacity(border.countryCode)),
        updateTriggers: { getColor: [selection, countryVolumes] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new CountryArcLayer<BundledMapArc>({
        ...arcProps, id: 'country-connections', data: countryRoutes, getWidth: 1.5,
        getSourceColor: arc => alpha(trackColor(arc.trackId), 0.5 * routeOpacity(arc)),
        getTargetColor: arc => alpha(trackColor(arc.trackId), 0.4 * routeOpacity(arc)),
      }),
      new CountryFlowArcLayer<TrafficArc>({
        ...arcProps, id: 'country-traffic', data: countryTraffic, time: frame / fps, motion: reducedMotion ? 0 : 1,
        phase: (cursorMs - trafficAnchorMs) / TRAFFIC_BUCKET_MS,
        getRadii0: arc => arc.radii.slice(0, 4), getRadii1: arc => arc.radii.slice(4, 8), getRadii2: arc => arc.radii.slice(8, 12),
        getDirection: arc => arc.direction ?? 1,
        getSourceColor: arc => alpha(trackColor(arc.trackId), routeOpacity(arc)),
        getTargetColor: arc => alpha(trackColor(arc.trackId), routeOpacity(arc)),
      }),
      new PathLayer<MapPosition[]>({
        id: 'atlas-grid', data: GRATICULE, getPath: (path) => path,
        getColor: [69, 102, 118, 27], getWidth: 1, widthUnits: 'pixels', pickable: false,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, data: measuredSpans, id: 'route-glow',
        getSourceColor: (arc) => alpha(trackColor(arc.trackId), 0.06 * routeOpacity(arc)),
        getTargetColor: (arc) => alpha(trackColor(arc.trackId), 0.04 * routeOpacity(arc)), getWidth: 3,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, data: measuredSpans, id: 'connection-strips', getWidth: 1,
        getSourceColor: (arc) => alpha(trackColor(arc.trackId), 0.44 * routeOpacity(arc)),
        getTargetColor: (arc) => alpha(trackColor(arc.trackId), 0.34 * routeOpacity(arc)),
      }),
      new GapArcLayer<BundledMapArc>({
        ...arcProps, data: unknownSpans, id: 'unknown-route-spans', getWidth: 1,
        getSourceColor: (arc) => alpha(trackColor(arc.trackId), 0.48 * routeOpacity(arc)),
        getTargetColor: (arc) => alpha(trackColor(arc.trackId), 0.38 * routeOpacity(arc)),
      }),
      new PathLayer<TrafficPathStrip>({
        id: 'traceroute-strips', data: tracedStrips, getPath: strip => strip.path,
        getColor: strip => alpha(trackColor(strip.trackId), 0.5 * trackOpacity(strip.trackId, selection)),
        getWidth: 1, widthUnits: 'pixels', jointRounded: true, capRounded: true,
        visible: showTraffic, wrapLongitude: true,
        updateTriggers: { getColor: selection }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      ...volumeLayers.map(({ focused, data }) => new FlowArcLayer<TrafficArc>({
        ...arcProps, data, id: focused ? 'traffic-streams' : 'muted-traffic-streams', time: frame / fps, motion: reducedMotion ? 0 : 1,
        phase: (cursorMs - trafficAnchorMs) / TRAFFIC_BUCKET_MS,
        getRadii0: (arc) => arc.radii.slice(0, 4), getRadii1: (arc) => arc.radii.slice(4, 8), getRadii2: (arc) => arc.radii.slice(8, 12),
        getProgress: (arc) => [arc.progressStart ?? 0, arc.progressEnd ?? 1],
        getDirection: arc => arc.direction ?? 1,
        getSourceColor: (arc) => alpha(trackColor(arc.trackId), routeOpacity(arc)),
        getTargetColor: (arc) => alpha(trackColor(arc.trackId), 0.92 * routeOpacity(arc)),
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused },
      })),
      ...pathVolumeLayers.map(({ focused, data }) => new FlowPathLayer<TrafficPathEdge>({
        id: focused ? 'traceroute-streams' : 'muted-traceroute-streams', data,
        time: frame / fps, motion: reducedMotion ? 0 : 1, phase: (cursorMs - trafficAnchorMs) / TRAFFIC_BUCKET_MS,
        getSourcePosition: edge => edge.sourcePosition, getTargetPosition: edge => edge.targetPosition,
        getPreviousPosition: edge => edge.previousPosition, getNextPosition: edge => edge.nextPosition,
        getProgress: edge => edge.progress,
        getDirection: edge => edge.direction ?? 1,
        getRadii0: edge => edge.radii.slice(0, 4), getRadii1: edge => edge.radii.slice(4, 8), getRadii2: edge => edge.radii.slice(8, 12),
        getSourceColor: edge => alpha(trackColor(edge.trackId), trackOpacity(edge.trackId, selection)),
        getTargetColor: edge => alpha(trackColor(edge.trackId), trackOpacity(edge.trackId, selection)),
        visible: showTraffic, updateTriggers: { getSourceColor: selection, getTargetColor: selection },
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused },
      })),
      new ScatterplotLayer<MapHopPoint>({
        id: 'route-hops', data: visibleHops, visible: showTraffic, pickable: true,
        getPosition: (hop) => hop.position, radiusUnits: 'pixels', getRadius: 4,
        filled: true, stroked: true, getFillColor: (hop) => [11, 24, 34, 240 * trackOpacity(hop.trackId, selection)],
        getLineColor: (hop) => alpha(trackColor(hop.trackId), 0.85 * trackOpacity(hop.trackId, selection)),
        getLineWidth: 1.5, lineWidthUnits: 'pixels',
        updateTriggers: { getLineColor: selection, getFillColor: selection }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new TextLayer<MapHopPoint>({
        id: 'route-hop-order', data: visibleHops.filter(hop => hop.trackId === selection),
        visible: showTraffic && viewState.zoom >= 3, getPosition: hop => hop.position,
        getText: hop => `HOP ${hop.ttl}`, getSize: 9, getColor: [195, 217, 224, 255],
        getPixelOffset: [0, -16], fontFamily: 'system-ui, sans-serif', fontWeight: 500,
        background: true, getBackgroundColor: [10, 23, 32, 220], backgroundPadding: [5, 3],
        parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destination-halos', data: cityPoints, getPosition: (point) => point.position,
        radiusUnits: 'pixels', getRadius: (point) => point.trackId === selection ? 17 : 10,
        getFillColor: (point) => alpha(trackColor(point.trackId), (point.activeFlowCount > 0 ? 0.08 : 0.04) * trackOpacity(point.trackId, selection)),
        updateTriggers: { getRadius: selection, getFillColor: selection }, parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destinations', data: cityPoints, pickable: true, radiusUnits: 'pixels', stroked: true,
        getPosition: (point) => point.position, getRadius: (point) => point.trackId === selection ? 5.5 : 3.5,
        getFillColor: (point) => alpha(trackColor(point.trackId), (point.activeFlowCount > 0 ? 1 : 0.55) * trackOpacity(point.trackId, selection)),
        getLineColor: (point) => point.trackId === selection ? [230, 255, 248, 255] : [11, 24, 34, 230 * trackOpacity(point.trackId, selection)],
        getLineWidth: 1.5, lineWidthUnits: 'pixels',
        updateTriggers: { getRadius: selection, getFillColor: selection, getLineColor: selection }, parameters: { depthCompare: 'always' },
      }),
      ...columnLayers.map(({ focused, data }) => new ColumnLayer<DestinationColumn>({
        id: focused ? 'destination-columns' : 'muted-destination-columns', data, pickable: true,
        diskResolution: 6, radius: 6, radiusUnits: 'pixels', angle: 30, extruded: true, flatShading: true,
        getPosition: column => [...column.destination.position, column.base * columnMetersPerPixel(column.destination.position[1], viewState.zoom)],
        getElevation: column => column.height * columnMetersPerPixel(column.destination.position[1], viewState.zoom),
        getFillColor: column => alpha(trackColor(column.trackId), 0.92 * trackOpacity(column.trackId, selection)),
        material: { ambient: 0.38, diffuse: 0.7, shininess: 45, specularColor: [130, 170, 180] },
        updateTriggers: { getPosition: viewState.zoom, getElevation: viewState.zoom, getFillColor: selection },
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused },
      })),
      new TextLayer<DestinationVolume>({
        id: 'destination-totals', data: destinationLabels,
        getPosition: destination => [...destination.position, destination.height * columnMetersPerPixel(destination.position[1], viewState.zoom)],
        getText: destination => `${destination.estimated ? '≈ ' : ''}${formatBytes(destination.bytes)}`,
        characterSet: '0123456789. BkMG≈',
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
        id: 'gateway-label', data: origin, getPosition: (point) => point.position,
        getText: () => 'GATEWAY', getSize: 10, getColor: [175, 218, 209, 255],
        getPixelOffset: [0, 26], fontFamily: 'system-ui, sans-serif', fontWeight: 600,
        background: true, getBackgroundColor: [10, 23, 32, 230], backgroundPadding: [7, 4],
        getTextAnchor: 'middle', getAlignmentBaseline: 'center', parameters: { depthCompare: 'always' },
      }),
    ]
  }, [cursorMs, fps, frame, routes, measuredSpans, unknownSpans, tracedStrips, pathVolumeLayers, origin, reducedMotion, selection, showTraffic, trafficAnchorMs, trackCatalog, visibleHops, viewState.zoom, volumeLayers, columnLayers, destinationLabels, countryPolygons, countryBorders, countryVolumes, countryRoutes, countryTraffic, cityPoints])

  function moveTo(next: Partial<MapViewState>) {
    setViewState((current) => ({ ...current, ...next, transitionDuration: reducedMotion ? 0 : 700, transitionInterpolator: new FlyToInterpolator() }))
  }

  function fitNetwork(trackId?: string) {
    const positions = [origin[0].position, ...[...visiblePoints, ...visibleHops].filter(point => !trackId || point.trackId === trackId).flatMap(point => 'country' in point && point.country ? countryFitPositions(point.country) : [point.position])]
    // Unwrap around the gateway so dateline routes take the short way around.
    const longitudes = positions.map(([lon]) => scene.origin.longitude + ((lon - scene.origin.longitude + 540) % 360) - 180)
    const latitudes = positions.map(([, lat]) => Math.max(-80, Math.min(80, lat)))
    const padding = width > 760 ? { left: 340, right: selection && width > 1000 ? 390 : 100, top: 100, bottom: 100 } : { left: 50, right: 50, top: 75, bottom: 220 }
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

  return (
    <AbsoluteFill className="atlas-composition" data-map-zoom={viewState.zoom.toFixed(2)} data-map-pitch={viewState.pitch} data-route-mode={showRoutes ? 'traceroute' : 'direct'} data-selected-track={selection || undefined} data-track-count={trackFrame.tracks.length} data-destination-count={destinations.length} data-country-count={countryDestinations.length} data-city-column-count={columns.length} data-destination-bytes={Math.round(destinations.reduce((sum, destination) => sum + destination.bytes, 0))}>
      <DeckGL
        controller={{ dragRotate: true, touchRotate: true }} viewState={viewState}
        onViewStateChange={({ viewState: next }) => setViewState(next as MapViewState)}
        layers={layers} getTooltip={info => {
          if (info.layer?.id === 'country-footprints' && info.object) {
            const destination = countryVolumes.get(info.object.countryCode)
            return destination ? { text: `${destination.location} · Country estimate\nCity unknown\n${formatBytes(destination.bytes)} accumulated (sent + received)\nClick for country totals and tracks` } : null
          }
          return tooltipForPoint(info)
        }}
        onClick={({ object, layer }) => {
          if (layer?.id === 'country-footprints' && object) { setSelectedCountry(countryVolumes.get(object.countryCode)?.id ?? null); return }
          if (['destinations', 'route-hops', 'destination-columns', 'muted-destination-columns'].includes(layer?.id ?? '') && object) selectTrack((object as MapPoint | MapHopPoint | DestinationColumn).trackId ?? null) }}
        getCursor={({ isDragging, isHovering }) => isDragging ? 'grabbing' : isHovering ? 'pointer' : 'grab'}
      >
        <MapLibre reuseMaps mapStyle={mapStyleUrl} minZoom={-1} attributionControl={{ compact: true }}
          onError={() => setMapError(true)} onIdle={() => setMapError(false)} />
      </DeckGL>
      <div className="atlas-vignette" />
      <CountryLabels destinations={countryDestinations} viewState={viewState} width={width} height={height} selection={selection} selectedCountry={selectedCountry} colors={trackCatalog.colors} onCountry={setSelectedCountry} onTrack={selectTrack} />

      <aside className="atlas-overview" aria-label="Traffic overview">
        <div className="atlas-eyebrow"><span className="atlas-tiny-line" /> SESSION INTELLIGENCE</div>
        <h1>Traffic overview</h1>
        <div className="atlas-metrics">
          <div><span className="atlas-metric-value atlas-accent">{activeFlowCount.toLocaleString()}</span><span className="atlas-metric-label"><i className="atlas-dot" />Active flows</span></div>
          <div><span className="atlas-metric-value">{trackFrame.tracks.length.toLocaleString()}</span><span className="atlas-metric-label">Tracks</span></div>
          <div><span className="atlas-metric-value atlas-metric-bytes">{volumeValue}<small>{volumeUnit}</small></span><span className="atlas-metric-label">Observed volume</span></div>
          <div><span className="atlas-metric-value">{countries}</span><span className="atlas-metric-label">Countries</span></div>
        </div>
        <MapTrackList tracks={trackFrame.tracks} selectedId={selection} activeOnly={activeOnly} onActiveOnly={setActiveOnly} onSelect={selectTrack} />

      </aside>

      <div className="atlas-map-heading"><MapIcon name="globe" size={15} /><span>NETWORK ATLAS</span><i /><span className="atlas-map-heading-detail">Geographic view</span></div>
      <div className="atlas-view-options">
        <div className="atlas-segmented atlas-view-switch" aria-label="Map perspective">
          <button type="button" aria-pressed={viewState.pitch !== 0} onClick={() => moveTo({ pitch: 35 })}>Perspective</button>
          <button type="button" aria-pressed={viewState.pitch === 0} onClick={() => moveTo({ pitch: 0, bearing: 0 })}>Top-down</button>
        </div>
        <button type="button" className="atlas-layer-button" aria-pressed={showRoutes} onClick={() => setShowRoutes(value => !value)} title={showRoutes ? 'Show direct connections' : 'Show traceroute paths'}><MapIcon name="route" size={16} /><span>Routes</span><i className="atlas-dot" /></button>
        <button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic((value) => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button>
      </div>

      {selected && selectedTraffic && <MapTrackInspector key={selected.id} track={selected} catalog={trackCatalog} cursorMs={projectedCursorMs} traffic={selectedTraffic} onClose={() => selectTrack(null)} onFit={() => fitNetwork(selected.id)} />}

      {scene.endpoints.length === 0 && <div className="atlas-empty"><MapIcon name="globe" size={30} /><h2>{unavailable ? 'Session data unavailable' : loading ? 'Connecting to your session' : 'No mapped destinations yet'}</h2><p>{unavailable ? 'Check the gateway connection and try again.' : loading ? 'Loading the network view…' : 'Geolocated traffic will appear here as it is observed.'}</p></div>}
      {mapError && <div className="atlas-map-error" role="status">Basemap tiles are unavailable. Traffic is still shown.</div>}

      <div className="atlas-map-tools" aria-label="Map controls">
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.min(16, viewState.zoom + 1) })} aria-label="Zoom in" title="Zoom in"><MapIcon name="plus" /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.max(-1, viewState.zoom - 1) })} aria-label="Zoom out" title="Zoom out"><MapIcon name="minus" /></button>
        <span />
        <button type="button" className="atlas-icon-button" onClick={() => fitNetwork()} aria-label="Fit network" title="Fit network"><MapIcon name="expand" size={17} /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ longitude: scene.origin.longitude, latitude: scene.origin.latitude, zoom: 5, bearing: 0 })} aria-label="Center on gateway" title="Center on gateway"><MapIcon name="target" /></button>
      </div>
      <div className="atlas-map-footer"><div className="atlas-legend"><span><i className="atlas-route-swatch" />Connection</span><span><i className="atlas-volume-swatch" />Traffic / sec</span><span><i className="atlas-column-swatch" />City accumulation</span>{countryDestinations.length > 0 && <span><i className="atlas-country-swatch" />Country estimate</span>}{visibleHops.length > 0 && <span><i className="atlas-hop-swatch" />Router</span>}<span><i className="atlas-gateway-swatch" />Gateway</span></div><p className="atlas-column-scale" data-volume-source={destinationLoading ? 'loading' : destinationError ? 'unavailable' : destinationEstimated ? 'estimated' : destinationPartial ? 'partial' : 'captured'}>Totals = sent + received · Columns use log scale{destinationLoading ? ' · Loading totals…' : destinationError ? ' · Capture history unavailable' : destinationEstimated ? ' · ≈ includes estimates' : destinationPartial ? ' · Partial capture' : ''}</p><p className="atlas-traffic-scale" data-traffic-source={estimatedTraffic ? 'estimated' : partialTraffic ? 'partial' : 'sampled'}>Track colors{trafficLoading ? ' · Loading samples' : estimatedTraffic ? ' · Estimated rates' : partialTraffic ? ' · Partial measurements' : ''}</p><p>{!showRoutes ? 'Simplified connections · ' : hasUnknownSpans ? 'Dashed spans = unknown path · ' : 'Approximate routes · '}Coarse IP locations</p></div>
    </AbsoluteFill>
  )
}

function alpha(color: Color, opacity: number): Color {
  return [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)]
}

function tooltipForPoint({ object, layer }: PickingInfo<MapPoint | MapHopPoint | DestinationColumn>) {
  if (!object || !['destinations', 'route-hops', 'destination-columns', 'muted-destination-columns'].includes(layer?.id ?? '')) return null
  const destination = 'destination' in object ? object.destination : null
  const lines = 'destination' in object && destination
    ? [destination.location, `${formatBytes(destination.bytes)} accumulated`,
      `↓ ${formatBytes(destination.received)} received from this location`, `↑ ${formatBytes(destination.sent)} sent to this location`,
      `${destination.ips.length} ${destination.ips.length === 1 ? 'destination' : 'destinations'} · ${destination.flowCount} connections`,
      `${object.label} · ${formatBytes(object.bytes)} of total`,
      destination.estimated ? 'Includes flow-counter estimates; timing interpolated' : `Captured wire bytes · Growth interpolated${destination.partial ? ' · Partial capture' : ''}`,
      'Click to inspect traffic track']
    : 'ttl' in object
    ? [`Hop ${object.ttl} · ${object.label}`, object.address, object.rttMs === null ? '' : `${object.rttMs.toFixed(1)} ms round trip from gateway`, 'Click to inspect traffic track']
    : 'ip' in object ? [object.label, object.location, object.ip, `${object.flowCount.toLocaleString()} flows`, 'Click to inspect traffic track'] : []
  return {
    text: lines.filter(Boolean).join('\n'),
    style: { backgroundColor: '#11232e', color: '#e1eeed', fontSize: '12px', lineHeight: '1.7', border: '1px solid #30464f', borderRadius: '8px', padding: '12px 16px' },
  }
}
