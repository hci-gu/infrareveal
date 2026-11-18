import type { MapProps } from 'react-map-gl/maplibre'
import { FlyToInterpolator, WebMercatorViewport } from '@deck.gl/core'
import type { Color, MapViewState, PickingInfo } from '@deck.gl/core'
import { ArcLayer, ColumnLayer, PathLayer, ScatterplotLayer, SolidPolygonLayer, TextLayer } from '@deck.gl/layers'
import { AnimatedMercator } from './AnimatedMercator'
import type { MapRendererProps } from '../map/MapWorkspaceView'
import { createMapGeometryCache, sameTrafficArcGeometry } from '../map/mapGeometryCache'
import { lazy, Suspense, useEffect, useImperativeHandle, useMemo, useRef, useState } from 'react'
import type { MapPoint, MapPosition } from '../map/mapModel'
import { projectMapFrame } from '../map/mapModel'
import { FlowArcLayer } from '../map/FlowArcLayer'
import { flowPathPosition, FlowPathLayer } from '../map/FlowPathLayer'
import { MapIcon } from '../map/MapIcon'
import { formatBytes } from '../map/format'
import type { BundledMapArc } from '../map/bundleMapArcs'
import { connectionHasTrack } from '../map/bundleMapArcs'
import { directionalVolumeArcs, TRAFFIC_BUCKET_MS, TRAFFIC_HISTORY_LENGTH, trafficRadius } from '../map/mapTraffic'
import type { TrafficArc, TrafficProfile } from '../map/mapTraffic'
import { trackOpacity } from '../map/mapTracks'
import { directionColor } from '../map/mapWorkspace'
import { CountryLabels } from '../map/CountryLabels'
import { layoutMapLabels } from '../map/labelLayout'
import { CountryArcLayer, CountryFlowArcLayer, CountryFootprintLayer } from '../map/CountryLayers'
import { countryFitPositions, countryFootprint } from '../map/countryFootprints'
import { columnMetersPerPixel, projectDestinationVolumes, directionalColumns } from '../map/destinationVolumes'
import countries from '../map/data/countries.json'
import { mapProjection } from '../map/mapProjection'
import { buildSeaNetwork, CABLE_SOURCE, CABLES, hopLabel, routeChoice, splitAntimeridian } from '../map/seaCrossings'
import type { SeriesRoute } from '../map/seaCrossings'
import type { CrossingConfidence, SeaHop } from '../map/seaCrossings'
import { bearingDegrees, fibreFloorMs, formatRtt, LATENCY_RINGS, latencyPosition, latencyRing, placement, UNMEASURED_RING_MS } from '../map/latency'
import type { Placement } from '../map/latency'
import type { DestinationColumn, DestinationVolume, DirectionalColumn } from '../map/destinationVolumes'

const TiledBasemap = lazy(() => import('../map/TiledBasemap'))
function Basemap(props: MapProps) { return <Suspense fallback={null}><TiledBasemap {...props} /></Suspense> }

const TEAL: Color = [88, 222, 192, 235]
/** Bundled Natural Earth land, drawn where online tiles cannot be (non-Mercator projections). */
const WORLD = (countries as { code: string; name: string; position: MapPosition; polygons: MapPosition[][][] }[])
const WORLD_POLYGONS = WORLD.flatMap(country => country.polygons)
const WORLD_RINGS = WORLD_POLYGONS.flat()
/** Mirrors the land, water and boundary colors of the tiled atlas style. */
const BASE_COLORS = {
  dark: { land: [26, 35, 40], water: [10, 18, 22], border: [63, 74, 80], label: [118, 131, 137] },
  light: { land: [210, 222, 217], water: [237, 243, 243], border: [159, 176, 170], label: [106, 127, 131] },
} satisfies Record<string, Record<string, Color>>
const MAX_ROUTE_WIDTH = 14
/** Labelled sea crossings at once; the rest stay unlabelled to keep the map readable. */
const MAX_CROSSING_LABELS = 5
const cableById = new Map(CABLES.map(cable => [cable.id, cable]))

type FlowStyle = 'direct' | 'cables'
type Layout = 'geography' | 'latency'
/** Where a destination sits in the latency view, and what its round trip says about its IP location. */
type LatencyEntry = { position: MapPosition; bearing: number; rttMs?: number; source?: 'tcp' | 'udp'; floorMs: number; placement?: Placement; ghost?: MapPosition }
const positionKey = (position: readonly number[]) => `${position[0]},${position[1]}`
/** Positions slide between layouts with deck.gl attribute transitions, enabled only while switching. */
const LAYOUT_TRANSITION_MS = 1200
const LAYOUT_TRANSITIONS = { getPosition: LAYOUT_TRANSITION_MS, getSourcePosition: LAYOUT_TRANSITION_MS, getTargetPosition: LAYOUT_TRANSITION_MS }
/** One drawable flow segment of the inferred sea-crossing network. */
type FlowEdge = { id: string; kind: 'sea' | 'land'; received: number; sent: number; locationIds: string[]; trackIds: string[]; seriesIds: string[]; confidence?: CrossingConfidence | null; cableId?: string; hopId?: string; candidates?: number }
type FlowPath = { edge: FlowEdge; path: MapPosition[] }
/** One direction of live traffic along one drawn path; geometry is reused while the path is unchanged. */
type AnimatedFlow = { key: string; edgeId: string; direction: number; path: [number, number, number][] }
/** Static bands show the window's volume as context; the animated tubes on top carry the live rate. */
const FLOW_OPACITY: Record<FlowEdge['kind'], [band: number, sent: number]> = { sea: [0.4, 0.55], land: [0.18, 0.28] }
/** Candidate cables share a crossing's traffic, so each is dimmed by how many there are; `possible` crossings recede further. */
const flowOpacity = (edge: FlowEdge, layer: 0 | 1) => FLOW_OPACITY[edge.kind][layer]
  * (edge.kind === 'sea' ? (edge.confidence === 'possible' ? 0.65 : 1) / Math.sqrt(Math.min(edge.candidates ?? 1, 6)) : 1)
/** Approximate glyph advance for the uppercase country names, in pixels. */
const COUNTRY_NAME_CHAR_PX = 7

/** Country names with the drawn width of their largest landmass, in map degrees. */
function countryNames(toMap: (position: MapPosition) => MapPosition) {
  return WORLD.map(country => {
    const widths = country.polygons.map(polygon => { const xs = polygon[0].map(position => toMap(position)[0]); return Math.max(...xs) - Math.min(...xs) })
    return { name: country.name.toUpperCase(), position: toMap(country.position), width: Math.max(0, ...widths) }
  })
}

/**
 * The atlas renders every projection through one deck.gl Web Mercator view.
 * `projection.toMap` converts each geographic position at the layer boundary;
 * the composition is keyed by projection, so accessors never need re-triggering.
 */
export function MapComposition({ controlsRef, inspection, profiles: trafficProfiles, trafficAnchorMs, emptyState, cursorMs, preferences, theme, workspace, overview, scene, clock, width: compositionWidth, height: compositionHeight, playbackEpochMs, mapStyleUrl, trafficLoading, destinationIndex, destinationLoading }: MapRendererProps) {
  const projection = mapProjection(preferences.projection)
  const [layout, setLayout] = useState<Layout>('geography')
  const [switchingLayout, setSwitchingLayout] = useState(false)
  const pendingFit = useRef(false)
  /**
   * Latency layout: the gateway at the centre, each destination at its true
   * bearing and at a distance set by its lowest measured round trip. Unmeasured
   * destinations sit on an outer ring. Ghosts mark the fastest round trip
   * physics allows from each IP location.
   */
  const latency = useMemo(() => {
    if (layout !== 'latency') return null
    const entries = new Map<string, LatencyEntry>()
    for (const location of overview.locations) {
      if (!location.position) continue
      const bearing = bearingDegrees(scene.origin, location.position), floorMs = fibreFloorMs(scene.origin, location.position)
      const measured = location.rttMs
      entries.set(positionKey(location.position), {
        bearing, floorMs, rttMs: measured, source: location.rttSource,
        position: latencyPosition(measured ?? UNMEASURED_RING_MS, bearing),
        placement: measured === undefined ? undefined : placement(measured, floorMs),
        ghost: measured === undefined ? undefined : latencyPosition(floorMs, bearing),
      })
    }
    return { entries, key: [...entries].map(([key, entry]) => `${key}:${entry.position}`).sort().join('|') }
  }, [layout, overview.locations, scene.origin])
  const originKey = positionKey([scene.origin.longitude, scene.origin.latitude])
  const P = latency
    ? (position: MapPosition): MapPosition => latency.entries.get(positionKey(position))?.position
      ?? (positionKey(position) === originKey ? [0, 0] : latencyPosition(UNMEASURED_RING_MS, bearingDegrees(scene.origin, position)))
    : projection.toMap
  /** Accessors read positions through P; this changes whenever P would place something differently. */
  const positionTrigger = latency ? latency.key : 'geography'
  const transitions = switchingLayout ? LAYOUT_TRANSITIONS : undefined
  const geographic = !latency
  const wrap = geographic && projection.wrap
  function switchLayout(next: Layout) {
    if (next === layout) return
    pendingFit.current = true
    setLayout(next)
    setSwitchingLayout(true)
  }
  useEffect(() => {
    if (!switchingLayout) return
    const timer = setTimeout(() => setSwitchingLayout(false), LAYOUT_TRANSITION_MS + 100)
    return () => clearTimeout(timer)
  }, [switchingLayout])
  /** Column heights are pixel-sized, so scale by the latitude deck.gl actually draws at. */
  const metersPerPixel = (position: MapPosition, zoom: number) => columnMetersPerPixel(P(position)[1], zoom)
  const names = useMemo(() => { const { tiles, toMap } = mapProjection(preferences.projection); return tiles ? [] : countryNames(toMap) }, [preferences.projection])
  const width = compositionWidth > 760 ? compositionWidth - 290 : compositionWidth
  const height = compositionWidth > 760 ? compositionHeight : Math.max(100, compositionHeight - 260)
  const mapFrame = useMemo(() => projectMapFrame(overview.scene, cursorMs), [cursorMs, overview.scene])
  const [viewState, setViewState] = useState<MapViewState>(() => ({
    longitude: P([scene.origin.longitude, scene.origin.latitude])[0] - (width > 760 ? 42 : 0), latitude: Math.max(-55, Math.min(55, P([scene.origin.longitude, scene.origin.latitude])[1] - 16)),
    zoom: width > 760 ? 1.55 : 1.4, minZoom: -1, maxZoom: 16, pitch: 35, bearing: 0,
  }))
  const [showTraffic, setShowTraffic] = useState(true)
  const [chosenFlowStyle, setFlowStyle] = useState<FlowStyle>('direct')
  // Cables are geographic; the latency view always draws direct connections.
  const flowStyle: FlowStyle = layout === 'latency' ? 'direct' : chosenFlowStyle
  /** Cables view: hide the reference network and keep only cables traffic is inferred to have used. */
  const [usedCablesOnly, setUsedCablesOnly] = useState(false)
  const { seaNetwork, flowPaths, flowPeak, seaHops } = useMemo(() => {
    const { toMap, wrap } = mapProjection(preferences.projection)
    // Cable lines may run past ±180°; split them first so neither projection draws across the world.
    const lane = (path: MapPosition[]) => splitAntimeridian(path).map(part => part.map(toMap))
    const network = flowStyle === 'cables' ? buildSeaNetwork(overview.locations, scene.origin, overview.volumeBySeries) : null
    const seaHops = new Map(network?.hops.map(total => [total.hop.id, total.hop]) ?? [])
    const paths: FlowPath[] = network?.edges.flatMap(edge => edge.kind === 'sea' ? lane(edge.path).map(path => ({ edge, path })) : [{ edge, path: routeCurve(toMap(edge.path[0]), toMap(edge.path[1]), wrap) }]) ?? []
    return { seaNetwork: network, flowPaths: paths, flowPeak: network?.peak ?? 1, seaHops }
  }, [flowStyle, overview.locations, scene.origin, overview.volumeBySeries, preferences.projection])
  // The full cable network only depends on the projection; keep it out of the per-update memo above.
  const cablePaths = useMemo(() => {
    if (flowStyle !== 'cables') return []
    const { toMap } = mapProjection(preferences.projection)
    return CABLES.flatMap(cable => cable.lines.flatMap(line => splitAntimeridian(line).map(part => part.map(toMap))))
  }, [flowStyle, preferences.projection])
  const flowGeometry = useMemo(() => createFlowGeometryCache(), [])
  const animatedFlows = useMemo(() => flowGeometry(flowPaths), [flowGeometry, flowPaths])
  const flowEdges = useMemo(() => new Map(flowPaths.map(item => [item.edge.id, item.edge])), [flowPaths])
  const flowRadii = useMemo(() => flowRateRadii(seaNetwork?.routes, trafficProfiles, trafficAnchorMs), [seaNetwork, trafficProfiles, trafficAnchorMs])
  /** One label per crossing, placed on its best-ranked (first drawn) cable. */
  const crossingLabels = useMemo(() => (seaNetwork?.hops ?? []).slice(0, MAX_CROSSING_LABELS).flatMap(total => {
    const edge = seaNetwork!.edges.find(item => item.kind === 'sea' && item.hopId === total.hop.id)
    if (!edge) return []
    const part = splitAntimeridian(edge.path).sort((a, b) => distanceAlong(b) - distanceAlong(a))[0]
    const cables = total.hop.candidates.length
    return [{ edge, position: pointAlong(part, 0.5), text: `${hopLabel(total.hop)} · ${cables} ${cables === 1 ? 'cable' : 'cables'} · ${formatBytes(total.received + total.sent)}` }]
  }), [seaNetwork])
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
  const showCityNames = viewState.zoom >= CITY_NAME_ZOOM
  const columnLayers = useMemo(() => [
    { focused: false, data: selection ? columns.filter(column => column.trackId !== selection) : [] },
    { focused: true, data: selection ? columns.filter(column => column.trackId === selection) : columns },
  ], [selection, columns])
  const labelLayout = useMemo(() => {
    const viewport = new WebMercatorViewport({ ...viewState, width, height })
    const project = (position: MapPosition, elevation = 0) => viewport.project([...P(position), elevation]) as [number, number]
    const inspectorEdge = inspectorOpen && width > 1000
    const cities = destinations.filter(destination => !destination.country).map(destination => ({
      id: destination.id, bytes: destination.received + destination.sent, text: columnLabel(destination, showCityNames),
      top: project(destination.position, destination.height * metersPerPixel(destination.position, viewState.zoom)), base: project(destination.position),
      hidden: Boolean(selection && !destination.tracks.some(track => track.trackId === selection)),
    }))
    const countries = (width <= 760 && inspectorOpen) ? [] : countryDestinations.map(destination => {
      const ring = destination.country?.polygons.length ? countryFitPositions(destination.country).map(position => project(position)) : []
      const xs = ring.map(point => point[0]), ys = ring.map(point => point[1])
      return {
        id: destination.id, bytes: destination.received + destination.sent, anchor: project(destination.position),
        footprint: ring.length ? { width: Math.max(...xs) - Math.min(...xs), height: Math.max(...ys) - Math.min(...ys) } : { width: 0, height: 0 },
        name: destination.location, total: formatBytes(destination.received + destination.sent),
        selected: selectedLocation?.id === destination.id, dimmed: Boolean(selection && !destination.tracks.some(track => track.trackId === selection)),
      }
    })
    return layoutMapLabels({
      cities, countries,
      bounds: { left: 12, top: 75, right: width - (inspectorEdge ? 390 : 60), bottom: height - 95 },
      cityBounds: { left: 35, top: 90, right: inspectorEdge ? width - 385 : width - 55, bottom: height - 90 },
    })
  // eslint-disable-next-line react-hooks/exhaustive-deps -- P depends only on the projection (fixed per composition) and the latency layout
  }, [destinations, countryDestinations, viewState, width, height, selection, selectedLocation?.id, inspectorOpen, showCityNames, latency])
  /** Busiest crossings claim label space first; a label that would overlap one already placed is dropped. */
  const placedCrossingLabels = useMemo(() => {
    const { toMap } = mapProjection(preferences.projection)
    const viewport = new WebMercatorViewport({ ...viewState, width, height })
    const boxes: [number, number, number, number][] = []
    return crossingLabels.filter(label => {
      const [x, y] = viewport.project(toMap(label.position))
      const halfWidth = label.text.length * 3.4 + 8, top = y - 24, bottom = y
      if (x - halfWidth < 0 || x + halfWidth > width || top < 70 || bottom > height - 90) return false
      if (boxes.some(([left, upper, right, lower]) => x - halfWidth < right && x + halfWidth > left && top < lower && bottom > upper)) return false
      boxes.push([x - halfWidth, top, x + halfWidth, bottom])
      return true
    })
  }, [crossingLabels, viewState, width, height, preferences.projection])
  const destinationLabels = useMemo(() => {
    const ids = new Set(labelLayout.cities)
    return destinations.filter(destination => ids.has(destination.id))
  }, [destinations, labelLayout])
  const countryById = useMemo(() => new Map(countryDestinations.map(destination => [destination.id, destination])), [countryDestinations])
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
      data: connections, greatCircle: geographic && projection.greatCircle, wrapLongitude: wrap, numSegments: 160, transitions,
      getSourcePosition: (arc: BundledMapArc) => P(arc.sourcePosition),
      getTargetPosition: (arc: BundledMapArc) => P(arc.targetPosition),
      getHeight: 0.18, getTilt: 0,
      visible: showTraffic && flowStyle === 'direct', parameters: { depthCompare: 'always' as const, depthWriteEnabled: false },
      updateTriggers: { getSourceColor: [selection, theme], getTargetColor: [selection, theme], getSourcePosition: positionTrigger, getTargetPosition: positionTrigger },
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
    const base = BASE_COLORS[theme]
    const routeDimmed = (edge: FlowEdge) => Boolean((selection && !edge.trackIds.includes(selection)) || (selectedLocation && !edge.locationIds.includes(selectedLocation.id)))
    const routeWidth = (bytes: number) => bytes > 0 ? Math.max(1, MAX_ROUTE_WIDTH * bytes / Math.max(1, flowPeak)) : 0
    return [
      ...(projection.tiles || latency ? [] : [
        new SolidPolygonLayer<MapPosition[]>({
          id: 'world-water', data: projection.outline ? [projection.outline] : [], getPolygon: outline => outline,
          getFillColor: base.water, updateTriggers: { getFillColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
        }),
        new SolidPolygonLayer<MapPosition[][]>({
          id: 'world-land', data: WORLD_POLYGONS, getPolygon: polygon => polygon.map(ring => ring.map(P)), _normalize: true,
          getFillColor: base.land, updateTriggers: { getFillColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
        }),
        new PathLayer<MapPosition[]>({
          id: 'world-borders', data: WORLD_RINGS, getPath: ring => ring.map(P), getWidth: 0.7, widthUnits: 'pixels',
          getColor: alpha(base.border, 0.65), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
        }),
        new PathLayer<MapPosition[]>({
          id: 'world-edge', data: projection.outline ? [projection.outline] : [], getPath: outline => [...outline, outline[0]], getWidth: 1, widthUnits: 'pixels',
          getColor: alpha(base.border, 0.8), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
        }),
        // Like the tiled style's collision handling: a name appears once its country is wide enough to hold it.
        new TextLayer<(typeof names)[number]>({
          id: 'world-country-names', data: names.filter(country => country.width * 512 * 2 ** viewState.zoom / 360 > country.name.length * COUNTRY_NAME_CHAR_PX),
          visible: preferences.labels, getPosition: country => country.position, getText: country => country.name, characterSet: 'auto',
          getSize: viewState.zoom >= 3 ? 12 : 9, fontFamily: 'system-ui, sans-serif', getColor: alpha(base.label, viewState.zoom >= 3 ? 0.85 : 0.45),
          updateTriggers: { getColor: [theme, viewState.zoom >= 3], getSize: viewState.zoom >= 3 }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
        }),
      ]),
      new CountryFootprintLayer({
        id: 'country-footprints', data: countryPolygons, visible: geographic, getPolygon: shape => shape.polygon.map(ring => ring.map(P)), pickable: true,
        getFillColor: shape => alpha(countryColor(shape.countryCode), (0.16 + Math.min(0.2, Math.log2(1 + (countryVolumes.get(shape.countryCode)?.bytes ?? 0) / 4096) * 0.015)) * countryOpacity(shape.countryCode)),
        updateTriggers: { getFillColor: [selection, countryVolumes, theme] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new PathLayer({
        id: 'country-outlines', data: countryBorders, visible: geographic, getPath: border => border.path.map(P), getWidth: 1, widthUnits: 'pixels',
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
        id: 'atlas-grid', data: geographic ? projection.graticule : [], getPath: (path) => path,
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
      new PathLayer<MapPosition[]>({
        id: 'sea-cables', data: cablePaths, visible: !usedCablesOnly, getPath: path => path, widthUnits: 'pixels', getWidth: 1.5, capRounded: true, jointRounded: true,
        getColor: alpha(neutralColor(), 0.22), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new PathLayer<FlowPath>({
        id: 'flow-bands', data: flowPaths, visible: showTraffic, getPath: route => route.path, wrapLongitude: projection.wrap, pickable: true,
        widthUnits: 'pixels', capRounded: true, jointRounded: true, getWidth: route => routeWidth(route.edge.received + route.edge.sent),
        getColor: route => alpha(flowColor(-1), flowOpacity(route.edge, 0) * (routeDimmed(route.edge) ? 0.15 : 1)),
        updateTriggers: { getColor: [selection, selectedLocation?.id, theme] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new PathLayer<FlowPath>({
        id: 'flow-sent', data: flowPaths.filter(route => route.edge.sent > 0), visible: showTraffic, getPath: route => route.path, wrapLongitude: projection.wrap,
        widthUnits: 'pixels', capRounded: true, jointRounded: true, getWidth: route => routeWidth(route.edge.sent),
        getColor: route => alpha(flowColor(1), flowOpacity(route.edge, 1) * (routeDimmed(route.edge) ? 0.15 : 1)),
        updateTriggers: { getColor: [selection, selectedLocation?.id, theme] }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new FlowPathLayer<AnimatedFlow>({
        id: 'flow-traffic', data: animatedFlows, visible: showTraffic, animation, dataComparator: sameAnimatedFlows,
        getPath: flow => flow.path,
        getRadii0: flow => (flowRadii.get(`${flow.edgeId}|${flow.direction}`) ?? NO_RADII).slice(0, 4),
        getRadii1: flow => (flowRadii.get(`${flow.edgeId}|${flow.direction}`) ?? NO_RADII).slice(4, 8),
        getRadii2: flow => (flowRadii.get(`${flow.edgeId}|${flow.direction}`) ?? NO_RADII).slice(8, 12),
        getColor: flow => { const edge = flowEdges.get(flow.edgeId); return alpha(flowColor(flow.direction), edge && routeDimmed(edge) ? 0.12 : 1) },
        // Triggers are compared shallowly by key; wrap objects in arrays so a new Map counts as a change.
        updateTriggers: { getRadii0: [flowRadii], getRadii1: [flowRadii], getRadii2: [flowRadii], getColor: [selection, selectedLocation?.id, theme, flowEdges] },
        parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      new ScatterplotLayer<{ id: string; position: MapPosition }>({
        id: 'sea-landings', data: seaNetwork?.landings ?? [], visible: showTraffic, stroked: true, radiusUnits: 'pixels', getRadius: 3,
        getPosition: landing => P(landing.position), getFillColor: theme === 'light' ? [237, 243, 243, 255] : [11, 24, 34, 255],
        getLineColor: alpha(flowColor(-1), 0.8), getLineWidth: 1.2, lineWidthUnits: 'pixels', updateTriggers: { getFillColor: theme, getLineColor: theme }, parameters: { depthCompare: 'always' },
      }),
      new TextLayer<(typeof crossingLabels)[number]>({
        id: 'sea-crossing-labels', data: placedCrossingLabels, visible: showTraffic && preferences.labels, getPosition: label => P(label.position), getText: label => label.text,
        characterSet: 'auto', getSize: 11, fontFamily: 'system-ui, sans-serif', fontWeight: 600, getColor: [223, 240, 239, 255],
        background: true, getBackgroundColor: [10, 23, 32, 215], backgroundPadding: [6, 3], getPixelOffset: [0, -12], parameters: { depthCompare: 'always', depthWriteEnabled: false },
      }),
      ...(latency ? latencyLayers(latency.entries, neutralColor(), theme, preferences.labels) : []),
      new ScatterplotLayer<MapPoint>({
        id: 'destination-halos', data: cityPoints, getPosition: (point) => P(point.position),
        radiusUnits: 'pixels', getRadius: (point) => point.trackId === selection ? 17 : 10, transitions,
        getFillColor: (point) => alpha(neutralColor(), (point.activeSeriesCount > 0 ? 0.08 : 0.04) * trackOpacity(point.trackId, selection)),
        updateTriggers: { getRadius: selection, getFillColor: [selection, theme], getPosition: positionTrigger }, parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destinations', data: cityPoints, pickable: true, radiusUnits: 'pixels', stroked: true,
        getPosition: (point) => P(point.position), getRadius: (point) => point.trackId === selection ? 5.5 : 3.5, transitions,
        getFillColor: (point) => alpha(neutralColor(), (point.activeSeriesCount > 0 ? 1 : 0.55) * trackOpacity(point.trackId, selection)),
        getLineColor: (point) => point.trackId === selection ? [230, 255, 248, 255] : [11, 24, 34, 230 * trackOpacity(point.trackId, selection)],
        getLineWidth: 1.5, lineWidthUnits: 'pixels',
        updateTriggers: { getRadius: selection, getFillColor: [selection, theme], getLineColor: [selection, theme], getPosition: positionTrigger }, parameters: { depthCompare: 'always' },
      }),
      ...columnLayers.map(({ focused, data }) => new ColumnLayer<DirectionalColumn>({
        id: focused ? 'destination-columns' : 'muted-destination-columns', data, pickable: true,
        diskResolution: 6, radius: 6, radiusUnits: 'pixels', angle: 30, extruded: true, flatShading: true,
        getPosition: column => { const [lon, lat] = P(column.destination.position); return [lon + column.direction * 7 * 360 / (512 * 2 ** viewState.zoom), lat, column.base * columnMetersPerPixel(lat, viewState.zoom)] },
        getElevation: column => column.height * metersPerPixel(column.destination.position, viewState.zoom),
        getFillColor: column => alpha(flowColor(column.direction), 0.92 * trackOpacity(column.trackId, selection)),
        material: { ambient: 0.38, diffuse: 0.7, shininess: 45, specularColor: [130, 170, 180] },
        updateTriggers: { getPosition: [viewState.zoom, positionTrigger], getElevation: [viewState.zoom, positionTrigger], getFillColor: [selection, theme] },
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: focused }, transitions,
      })),
      new TextLayer<DestinationVolume>({
        id: 'destination-totals', data: destinationLabels,
        getPosition: destination => [...P(destination.position), destination.height * metersPerPixel(destination.position, viewState.zoom)],
        getText: destination => columnLabel(destination, showCityNames),
        visible: preferences.labels,
        // City names need their own glyphs (å, ü, …); totals alone keep the small fixed set.
        characterSet: showCityNames ? 'auto' : '0123456789. BkMGT≈↓↑',
        getSize: 11, getPixelOffset: [0, -14], fontFamily: 'system-ui, sans-serif', fontWeight: 600,
        getColor: [223, 240, 239, 255], background: true, getBackgroundColor: [10, 23, 32, 225], backgroundPadding: [6, 4],
        updateTriggers: { getPosition: [viewState.zoom, positionTrigger], getText: showCityNames }, parameters: { depthCompare: 'always', depthWriteEnabled: false }, transitions,
      }),
      new ScatterplotLayer({
        id: 'gateway-ring', data: origin, getPosition: (point) => P(point.position), transitions, updateTriggers: { getPosition: positionTrigger },
        radiusUnits: 'pixels', getRadius: 13, stroked: true, filled: true,
        getFillColor: [88, 222, 192, 20], getLineColor: [88, 222, 192, 120], getLineWidth: 1,
        lineWidthUnits: 'pixels', parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer({
        id: 'gateway-core', data: origin, getPosition: (point) => P(point.position), transitions, updateTriggers: { getPosition: positionTrigger },
        radiusUnits: 'pixels', getRadius: 5, stroked: true,
        getFillColor: [208, 255, 242, 255], getLineColor: TEAL, getLineWidth: 2,
        lineWidthUnits: 'pixels', parameters: { depthCompare: 'always' },
      }),
      new TextLayer({
        id: 'gateway-label', visible: preferences.labels, data: origin, getPosition: (point) => P(point.position), transitions, updateTriggers: { getPosition: positionTrigger },
        getText: () => 'GATEWAY', getSize: 10, getColor: [175, 218, 209, 255],
        getPixelOffset: [0, 26], fontFamily: 'system-ui, sans-serif', fontWeight: 600,
        background: true, getBackgroundColor: [10, 23, 32, 230], backgroundPadding: [7, 4],
        getTextAnchor: 'middle', getAlignmentBaseline: 'center', parameters: { depthCompare: 'always' },
      }),
    ].filter(layer => layer.props.visible !== false && (!Array.isArray(layer.props.data) || layer.props.data.length > 0))
  // eslint-disable-next-line react-hooks/exhaustive-deps -- P depends only on the projection (fixed per composition) and the latency layout
  }, [latency, transitions, animation, trafficProfiles, connections, origin, selection, selectedLocation, showTraffic, showCityNames, viewState.zoom, volumeLayers, columnLayers, destinationLabels, countryPolygons, countryBorders, countryVolumes, countryConnections, countryTraffic, cityPoints, theme, workspace.expanded, preferences.labels, usedCablesOnly, flowPaths, flowPeak, cablePaths, seaNetwork, placedCrossingLabels, names, animatedFlows, flowEdges, flowRadii])

  function moveTo(next: Partial<MapViewState>) {
    setViewState((current) => ({ ...current, ...next, transitionDuration: 700, transitionInterpolator: new FlyToInterpolator() }))
  }

  function fitNetwork(trackId?: string) {
    const positions = [origin[0].position, ...visiblePoints.filter(point => !trackId || point.trackId === trackId).flatMap(point => 'country' in point && point.country ? countryFitPositions(point.country) : [point.position])].map(P)
    const [originLon] = P(origin[0].position)
    // Unwrap around the gateway so dateline connections take the short way around (Mercator only).
    const unwrap = (lon: number) => wrap ? originLon + ((lon - originLon + 540) % 360) - 180 : lon
    const longitudes = positions.map(([lon]) => unwrap(lon))
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
      const tops = fittedDestinations.map(destination => {
        const [lon, lat] = P(destination.position)
        return [unwrap(lon), lat, destination.height * columnMetersPerPixel(lat, zoom)]
      })
      const projected = [...longitudes.map((lon, i) => [lon, latitudes[i]]), ...tops].map(position => camera.project(position))
      if (projected.every(([x, y]) => x >= padding.left && x <= width - padding.right && y >= padding.top && y <= height - padding.bottom)) break
      zoom = Math.max(-1, zoom - 0.1)
    }
    moveTo({ longitude: viewport.longitude, latitude: viewport.latitude, zoom, bearing: 0 })
  }

  useImperativeHandle(controlsRef, () => ({ fit: fitNetwork }))
  // After a layout switch, frame the new positions (P has changed by now).
  useEffect(() => {
    if (!pendingFit.current) return
    pendingFit.current = false
    fitNetwork()
  })

  return (
    <div className="atlas-map-surface" hidden={workspace.expanded} data-map-zoom={viewState.zoom.toFixed(2)} data-map-pitch={viewState.pitch} data-connection-count={connections.length + countryConnections.length} data-city-column-count={columns.length}>
      <AnimatedMercator clock={clock} active={!workspace.expanded && showTraffic && (trafficArcs.length + countryTraffic.length + animatedFlows.length > 0)} useDevicePixels deviceProps={{ webgl: { antialias: false, preserveDrawingBuffer: false, powerPreference: 'high-performance' } }}
        controller={{ dragRotate: true, touchRotate: true }} viewState={viewState}
        onViewStateChange={({ viewState: next }) => setViewState(next as MapViewState)}
        layers={layers} getTooltip={info => {
          if (info.layer?.id === 'flow-bands' && info.object) return flowTooltip((info.object as FlowPath).edge, seaHops)
          if (info.layer?.id === 'country-footprints' && info.object) {
            const destination = countryVolumes.get(info.object.countryCode)
            return destination ? { text: `${destination.location} · Country estimate\nCity unknown\n${formatBytes(destination.received + destination.sent)} downloaded + sent\nClick for country totals and tracks` } : null
          }
          if (info.layer?.id === 'latency-ghosts' && info.object) return ghostTooltip(info.object as LatencyEntry)
          return tooltipForPoint(info, latency ? position => latency.entries.get(positionKey(position)) : undefined)
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
        {projection.tiles && geographic && <Basemap mapStyle={mapStyleUrl} minZoom={-1} attributionControl={{ compact: true }}
          onError={() => setMapError(true)} onIdle={() => setMapError(false)} />}
      </AnimatedMercator>
      {preferences.labels && geographic && <CountryLabels labels={labelLayout.countries} destinations={countryById} selection={selection} selectedLocationId={selectedLocation?.id ?? null} onCountry={selectLocation} />}
      <div className="atlas-vignette" />

      <div className="atlas-map-heading"><span>Network atlas</span><span className="atlas-map-heading-detail">{latency ? 'Latency' : projection.label}</span></div>
      <div className="atlas-view-options">
        <div className="atlas-segmented atlas-view-switch" aria-label="Map perspective">
          <button type="button" aria-pressed={viewState.pitch !== 0} onClick={() => moveTo({ pitch: 35 })}>Perspective</button>
          <button type="button" aria-pressed={viewState.pitch === 0} onClick={() => moveTo({ pitch: 0, bearing: 0 })}>Top-down</button>
        </div>
        <div className="atlas-segmented atlas-view-switch" role="group" aria-label="Map layout">
          <button type="button" aria-pressed={layout === 'geography'} onClick={() => switchLayout('geography')} title="Place destinations by their IP location">Geography</button>
          <button type="button" aria-pressed={layout === 'latency'} onClick={() => switchLayout('latency')} title="Place destinations by measured round-trip time from the gateway">Latency</button>
        </div>
        {geographic && <div className="atlas-segmented atlas-view-switch" role="group" aria-label="Flow layout">
          <button type="button" aria-pressed={flowStyle === 'direct'} onClick={() => setFlowStyle('direct')} title="Draw each destination as a direct connection">Direct</button>
          <button type="button" aria-pressed={flowStyle === 'cables'} onClick={() => setFlowStyle('cables')} title="Show the sea crossings traffic likely took, inferred from IP location">Cables</button>
        </div>}
        {flowStyle === 'cables' && <button type="button" className="atlas-layer-button" aria-pressed={usedCablesOnly} onClick={() => setUsedCablesOnly(value => !value)} title="Show only cables that traffic is inferred to have crossed, hiding the rest of the cable network"><span>Used cables only</span><i className="atlas-dot" /></button>}
        <button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic((value) => !value)} title="Show or hide flowing traffic"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button>
      </div>


      {emptyState}
      {!projection.tiles && geographic && <a className="atlas-earth-credit" href="https://www.naturalearthdata.com/" target="_blank" rel="noreferrer">Natural Earth</a>}
      {mapError && projection.tiles && <div className="atlas-map-error" role="status">Basemap tiles are unavailable. Traffic is still shown.</div>}

      <div className="atlas-map-tools" aria-label="Map controls">
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.min(16, viewState.zoom + 1) })} aria-label="Zoom in" title="Zoom in"><MapIcon name="plus" /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.max(-1, viewState.zoom - 1) })} aria-label="Zoom out" title="Zoom out"><MapIcon name="minus" /></button>
        <span />
        <button type="button" className="atlas-icon-button" onClick={() => fitNetwork()} aria-label="Fit network" title="Fit network"><MapIcon name="expand" size={17} /></button>
        <button type="button" className="atlas-icon-button" onClick={() => { const [longitude, latitude] = P([scene.origin.longitude, scene.origin.latitude]); moveTo({ longitude, latitude, zoom: latency ? 3 : 5, bearing: 0 }) }} aria-label="Center on gateway" title="Center on gateway"><MapIcon name="target" /></button>
      </div>
      <div className="atlas-map-footer"><div className="atlas-legend"><span className="atlas-down"><i className="atlas-direction-swatch" />↓ Downloaded to your devices</span><span className="atlas-up"><i className="atlas-direction-swatch is-sent" />↑ Sent from your devices</span>{countryDestinations.length > 0 && <span><i className="atlas-country-swatch" />Country estimate</span>}</div><p>{latency ? latencyFooter(latency.entries) : seaNetwork ? seaFooter(seaNetwork) : 'Direct connections.'} {latency ? '' : 'Coarse IP locations.'}{(trafficLoading || partialTraffic) ? trafficLoading ? ' Loading rates.' : ' Partial rates.' : ''}</p></div>
      </div>

  )
}

/** Regional zoom: columns are far enough apart to carry a place name. */
const CITY_NAME_ZOOM = 4

function columnLabel(destination: DestinationVolume, withCity: boolean) {
  const total = formatBytes(destination.received + destination.sent)
  return withCity && destination.city ? `${destination.city} · ${total}` : total
}

function alpha(color: Color, opacity: number): Color {
  return [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)]
}

function tooltipForPoint({ object, layer }: PickingInfo<MapPoint | DestinationColumn>, latencyOf?: (position: MapPosition) => LatencyEntry | undefined) {
  if (!object || !['destinations', 'destination-columns', 'muted-destination-columns'].includes(layer?.id ?? '')) return null
  const destination = 'destination' in object ? object.destination : null
  const entry = latencyOf?.(destination?.position ?? (object as MapPoint).position)
  const lines = 'destination' in object && destination
    ? [destination.location, `${formatBytes(destination.received + destination.sent)} downloaded + sent`,
      `↓ ${formatBytes(destination.received)} downloaded from this location`, `↑ ${formatBytes(destination.sent)} sent to this location`,
      `${destination.ips.length} ${destination.ips.length === 1 ? 'destination' : 'destinations'} · ${destination.seriesCount} series`,
      `${object.label} · ${formatBytes(object.bytes)} of total`,
      `Captured wire bytes · completed sample bins${destination.partial ? ' · Partial capture' : ''}`,
      'Click to inspect this location']
    : 'ip' in object ? [object.label, object.location, object.ip, `${object.seriesCount.toLocaleString()} traffic series`, 'Click to inspect this location'] : []
  if (entry) lines.splice(1, 0, ...latencyLines(entry))
  return {
    text: lines.filter(Boolean).join('\n'),
    style: { backgroundColor: 'var(--color-paper-2)', color: 'var(--color-ink)', fontFamily: 'var(--font-body)', fontSize: 'var(--text-xs)', lineHeight: '1.6', border: '1px solid var(--color-rule-2)', borderRadius: 'var(--radius-panel)', padding: '12px 16px', boxShadow: 'var(--shadow-float)' },
  }
}

/**
 * A gently bent route segment, sampled in Web Mercator space so it is drawn
 * as a smooth planar curve in either projection. Bends are consistently
 * left-handed so sibling branches fan apart instead of overlapping.
 */
function routeCurve(from: MapPosition, to: MapPosition, wrap: boolean): MapPosition[] {
  const mercY = (lat: number) => Math.log(Math.tan(Math.PI / 4 + Math.max(-85, Math.min(85, lat)) * Math.PI / 360)) * 180 / Math.PI
  const lat = (y: number) => (2 * Math.atan(Math.exp(y * Math.PI / 180)) - Math.PI / 2) * 180 / Math.PI
  const x1 = from[0], y1 = mercY(from[1])
  const x2 = wrap ? x1 + ((to[0] - x1 + 540) % 360) - 180 : to[0], y2 = mercY(to[1])
  const cx = (x1 + x2) / 2 - (y2 - y1) * .14, cy = (y1 + y2) / 2 + (x2 - x1) * .14
  return Array.from({ length: 25 }, (_, i) => {
    const t = i / 24, u = 1 - t
    return [u * u * x1 + 2 * u * t * cx + t * t * x2, lat(u * u * y1 + 2 * u * t * cy + t * t * y2)]
  })
}

const CONFIDENCE_TEXT: Record<CrossingConfidence, string> = {
  required: 'Sea crossing required: no overland route exists',
  possible: 'Sea crossing likely: the usual route, though an overland one exists',
}

function flowTooltip(edge: FlowEdge, hops: Map<string, SeaHop>) {
  const bytes = `${formatBytes(edge.received + edge.sent)} · ↓ ${formatBytes(edge.received)} ↑ ${formatBytes(edge.sent)} · ${edge.locationIds.length} ${edge.locationIds.length === 1 ? 'location' : 'locations'}`
  if (edge.kind === 'sea' && edge.cableId) {
    const hop = edge.hopId ? hops.get(edge.hopId) : undefined
    const others = (hop?.candidates ?? []).filter(candidate => candidate.cable.id !== edge.cableId).map(candidate => candidate.cable.name)
    return { text: [
      cableById.get(edge.cableId)?.name ?? 'Submarine cable', hop ? hopLabel(hop) : '', edge.confidence ? CONFIDENCE_TEXT[edge.confidence] : '',
      `Traffic needing this crossing: ${bytes}`,
      others.length ? `One of ${others.length + 1} cables connecting these regions; also ${others.slice(0, 5).join(', ')}${others.length > 5 ? ` and ${others.length - 5} more` : ''}` : 'The only cable connecting these regions in the data',
      `Inferred from IP location; which cable carried the traffic is not observed. Cable data: ${CABLE_SOURCE.label}.`,
    ].filter(Boolean).join('\n') }
  }
  return { text: `Overland or coastal connection (not drawn to scale)\n${bytes}` }
}

function seaFooter(network: { totals: Record<string, number>; edgeNetworks: string[] }) {
  const total = Object.values(network.totals).reduce((sum, value) => sum + value, 0)
  const share = (bytes: number) => total ? `${Math.round(bytes / total * 100)}%` : '0%'
  const edge = network.totals.edge > 0 ? ` ${share(network.totals.edge)} is served by global edge networks (${network.edgeNetworks.join(', ')}) and not placed.` : ''
  return `Sea crossings inferred from IP location: ${share(network.totals.required)} required one, ${share(network.totals.possible)} likely. Highlighted cables are the candidates; which one carried the traffic is not observed.${edge} Cable data: ${CABLE_SOURCE.label}.`
}

/** Planar length in degrees; only used to compare and walk along schematic lanes. */
function distanceAlong(path: MapPosition[]) {
  return path.slice(1).reduce((sum, [x, y], i) => sum + Math.hypot(x - path[i][0], y - path[i][1]), 0)
}
function pointAlong(path: MapPosition[], fraction: number): MapPosition {
  let remaining = distanceAlong(path) * fraction
  for (let i = 1; i < path.length; i++) {
    const [x0, y0] = path[i - 1], [x1, y1] = path[i], step = Math.hypot(x1 - x0, y1 - y0)
    if (step >= remaining && step > 0) return [x0 + (x1 - x0) * remaining / step, y0 + (y1 - y0) * remaining / step]
    remaining -= step
  }
  return path[path.length - 1]
}

const NO_RADII = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)

/**
 * Live rate history per drawn edge and direction, on the arcs' radius scale.
 * Every bucket of a series' history is a burst that travels one candidate cable
 * per crossing: `routeChoice` picks it from the series and the bucket's data
 * time, so a burst keeps its cable as it moves and replays identically.
 */
function flowRateRadii(routes: Map<string, SeriesRoute> | undefined, profiles: Map<string, TrafficProfile>, anchorMs: number) {
  const rates = new Map<string, { rates: number[]; packets: number[] }>()
  const add = (key: string, i: number, rate: number, packets: number) => {
    const entry = rates.get(key) ?? { rates: new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0), packets: new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0) }
    entry.rates[i] += rate; entry.packets[i] += packets
    rates.set(key, entry)
  }
  for (const [seriesId, route] of routes ?? []) {
    const profile = profiles.get(seriesId)
    if (!profile) continue
    for (const direction of [1, -1]) {
      const rate = direction === 1 ? profile.outRates : profile.inRates, count = direction === 1 ? profile.outPackets : profile.inPackets
      for (let i = 0; i < TRAFFIC_HISTORY_LENGTH; i++) {
        const bytes = rate?.[i] ?? 0, packets = count?.[i] ?? 0
        if (bytes <= 0 && packets <= 0) continue
        // Bucket i of the history ends i buckets before the anchor.
        const atMs = anchorMs - (i + 1) * TRAFFIC_BUCKET_MS
        for (const id of route.fixed) add(`${id}|${direction}`, i, bytes, packets)
        route.hops.forEach((options, hop) => {
          for (const id of options[routeChoice(seriesId, hop, atMs, options.length)] ?? []) add(`${id}|${direction}`, i, bytes, packets)
        })
      }
    }
  }
  const radii = new Map<string, number[]>()
  for (const [key, entry] of rates) {
    const values = entry.rates.map((rate, i) => trafficRadius(rate, entry.packets[i]))
    if (values.some(value => value > 0)) radii.set(key, values)
  }
  return radii
}

/**
 * Animated paths in both directions, with per-vertex progress. Paths are split
 * at the antimeridian here (with progress carried across the cut), so the
 * layer never re-splits them and every vertex keeps its progress value.
 * Unchanged paths keep their objects, so deck.gl keeps their buffers.
 */
function createFlowGeometryCache() {
  let previous = new Map<string, AnimatedFlow>()
  return (paths: FlowPath[]) => {
    const next = new Map<string, AnimatedFlow>()
    const flows: AnimatedFlow[] = []
    paths.forEach(({ edge, path }) => {
      // Keyed by geometry, not list position: edges re-sort by volume on every update.
      const signature = `${edge.id}:${path.length}:${path[0]}:${path[path.length - 1]}`
      const parts = previous.has(`${signature}|1|0`) ? null : splitWithProgress(path)
      for (const direction of [1, -1]) {
        for (let part = 0; ; part++) {
          const key = `${signature}|${direction}|${part}`
          const cached = previous.get(key)
          const source = parts?.[part]
          if (!cached && !source) break
          const flow = cached ?? { key, edgeId: edge.id, direction, path: source!.path.map((point, i) => flowPathPosition(point, source!.progress[i], direction)) }
          next.set(key, flow); flows.push(flow)
        }
      }
    })
    previous = next
    return flows
  }
}
function splitWithProgress(path: MapPosition[]) {
  const lengths = [0]
  for (let i = 1; i < path.length; i++) lengths.push(lengths[i - 1] + Math.hypot(path[i][0] - path[i - 1][0], path[i][1] - path[i - 1][1]))
  const total = Math.max(lengths[lengths.length - 1], 1e-9)
  const wrap = (lon: number) => ((lon + 540) % 360) - 180
  const parts: { path: MapPosition[]; progress: number[] }[] = [{ path: [], progress: [] }]
  for (let i = 0; i < path.length; i++) {
    const point: MapPosition = [wrap(path[i][0]), path[i][1]], progress = lengths[i] / total
    if (i) {
      const prior: MapPosition = [wrap(path[i - 1][0]), path[i - 1][1]], priorProgress = lengths[i - 1] / total
      if (Math.abs(point[0] - prior[0]) > 180) {
        const edge = prior[0] > 0 ? 180 : -180
        const t = Math.abs(edge - prior[0]) / Math.max(360 - Math.abs(point[0] - prior[0]), 1e-9)
        const lat = prior[1] + (point[1] - prior[1]) * t, at = priorProgress + (progress - priorProgress) * t
        parts[parts.length - 1].path.push([edge, lat]); parts[parts.length - 1].progress.push(at)
        parts.push({ path: [[-edge, lat]], progress: [at] })
      }
    }
    parts[parts.length - 1].path.push(point); parts[parts.length - 1].progress.push(progress)
  }
  return parts.filter(part => part.path.length > 1)
}
function sameAnimatedFlows(data: unknown, oldData?: unknown) {
  return Array.isArray(data) && Array.isArray(oldData) && data.length === oldData.length && data.every((flow, i) => flow === oldData[i])
}

function latencyLines(entry: LatencyEntry) {
  if (entry.rttMs === undefined) return ['No round trip measured in this window (no new connection, or no reply)']
  const how = entry.source === 'udp' ? 'UDP first reply, an upper bound' : 'TCP handshake'
  return [
    `Round trip ${formatRtt(entry.rttMs)} · lowest in window (${how})`,
    `Fastest possible from its IP location: ${formatRtt(entry.floorMs)}`,
    entry.placement === 'contradicted'
      ? `Faster than light allows from there: served from within ~${Math.round(entry.rttMs * 100).toLocaleString()} km`
      : 'Consistent with its IP location',
  ]
}

function ghostTooltip(entry: LatencyEntry) {
  return { text: [`Fastest possible round trip from its IP location: ${formatRtt(entry.floorMs)}`, `Measured: ${formatRtt(entry.rttMs!)}`, entry.placement === 'contradicted' ? 'The measurement is faster: the traffic was served from closer than its IP location' : 'Measured is slower: routing, queueing and server time add to the physical minimum'].join('\n') }
}

/** Rings at fixed round trips, their labels, and ghost markers for the physical floor of each IP location. */
function latencyLayers(entries: Map<string, LatencyEntry>, neutral: Color, theme: 'dark' | 'light', labels: boolean) {
  const rings = [...LATENCY_RINGS.map(ms => ({ ms, unmeasured: false })), { ms: UNMEASURED_RING_MS, unmeasured: true }]
  const ghosts = [...entries.values()].filter(entry => entry.ghost)
  const label: Color = theme === 'light' ? [71, 96, 101, 255] : [153, 167, 173, 255]
  return [
    new PathLayer<(typeof rings)[number]>({
      id: 'latency-rings', data: rings, getPath: ring => latencyRing(ring.ms), widthUnits: 'pixels', getWidth: ring => ring.unmeasured ? 1 : 1.2,
      getColor: ring => alpha(neutral, ring.unmeasured ? 0.12 : 0.28), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
    }),
    new TextLayer<(typeof rings)[number]>({
      id: 'latency-ring-labels', data: rings, visible: labels, getPosition: ring => latencyPosition(ring.ms, 0),
      getText: ring => ring.unmeasured ? 'NO MEASUREMENT' : `${ring.ms} ms`, getSize: 10, fontFamily: 'system-ui, sans-serif', fontWeight: 600,
      getColor: label, background: true, getBackgroundColor: theme === 'light' ? [237, 243, 243, 220] : [10, 18, 22, 220], backgroundPadding: [4, 2],
      updateTriggers: { getColor: theme, getBackgroundColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
    }),
    new TextLayer<{ text: string; bearing: number }>({
      id: 'latency-compass', data: [{ text: 'N', bearing: 0 }, { text: 'E', bearing: 90 }, { text: 'S', bearing: 180 }, { text: 'W', bearing: 270 }],
      getPosition: point => latencyPosition(UNMEASURED_RING_MS * 1.18, point.bearing), getText: point => point.text, getSize: 11,
      fontFamily: 'system-ui, sans-serif', fontWeight: 700, getColor: alpha(label, 0.7), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
    }),
    new PathLayer<LatencyEntry>({
      id: 'latency-ghost-links', data: ghosts, getPath: entry => [entry.ghost!, entry.position], widthUnits: 'pixels', getWidth: entry => entry.placement === 'contradicted' ? 1.5 : 1,
      getColor: entry => alpha(neutral, entry.placement === 'contradicted' ? 0.55 : 0.2), updateTriggers: { getColor: theme }, parameters: { depthCompare: 'always', depthWriteEnabled: false },
    }),
    new ScatterplotLayer<LatencyEntry>({
      id: 'latency-ghosts', data: ghosts, pickable: true, getPosition: entry => entry.ghost!, radiusUnits: 'pixels', getRadius: 4,
      stroked: true, filled: false, getLineColor: entry => alpha(neutral, entry.placement === 'contradicted' ? 0.8 : 0.35), getLineWidth: 1.2, lineWidthUnits: 'pixels',
      updateTriggers: { getLineColor: theme }, parameters: { depthCompare: 'always' },
    }),
  ]
}

function latencyFooter(entries: Map<string, LatencyEntry>) {
  const values = [...entries.values()]
  const unmeasured = values.filter(entry => entry.rttMs === undefined).length
  const contradicted = values.filter(entry => entry.placement === 'contradicted').length
  return [
    'Distance from the centre is the lowest round trip measured passively at the gateway in this window; direction is the true compass bearing.',
    'Hollow markers show the fastest round trip physics allows from each IP location.',
    contradicted ? `${contradicted} ${contradicted === 1 ? 'destination answers' : 'destinations answer'} faster than that, so ${contradicted === 1 ? 'it was' : 'they were'} served from nearby.` : '',
    unmeasured ? `${unmeasured} without a measurement on the outer ring.` : '',
  ].filter(Boolean).join(' ')
}
