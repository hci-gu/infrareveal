import { FlyToInterpolator, WebMercatorViewport } from '@deck.gl/core'
import type { Color, MapViewState, PickingInfo } from '@deck.gl/core'
import { ArcLayer, PathLayer, ScatterplotLayer, TextLayer } from '@deck.gl/layers'
import DeckGL from '@deck.gl/react'
import type { StyleSpecification } from 'maplibre-gl'
import { useEffect, useMemo, useState } from 'react'
import Map from 'react-map-gl/maplibre'
import { AbsoluteFill, useCurrentFrame, useVideoConfig } from 'remotion'
import { timeForFrame } from '@infrareveal/session-state'
import type { MapPoint, MapPosition, MapTimelineScene } from '../map/mapModel'
import { projectMapFrame } from '../map/mapModel'
import { FlowArcLayer } from '../map/FlowArcLayer'
import { MapIcon } from '../map/MapIcon'
import { formatBytes } from '../map/format'
import { bundleMapArcs } from '../map/bundleMapArcs'
import type { BundledMapArc } from '../map/bundleMapArcs'
import { projectTrafficProfiles, TRAFFIC_BUCKET_MS, volumeArcs } from '../map/mapTraffic'
import type { MapTrafficIndex, TrafficArc } from '../map/mapTraffic'

export type MapCompositionProps = {
  scene: MapTimelineScene
  fps: number
  mapStyleUrl: string | StyleSpecification
  unavailable: boolean
  loading: boolean
  trafficIndex: MapTrafficIndex
  trafficLoading: boolean
}

const MAP_PROJECTION_INTERVAL_MS = 250
const TEAL: Color = [88, 222, 192, 235]
const BLUE: Color = [115, 170, 235, 220]
const GRATICULE: MapPosition[][] = [
  ...Array.from({ length: 13 }, (_, index) => [[-180 + index * 30, -80], [-180 + index * 30, 80]] as MapPosition[]),
  ...Array.from({ length: 5 }, (_, index) => Array.from({ length: 37 }, (_, x) => [-180 + x * 10, -60 + index * 30] as MapPosition)),
]

export function MapComposition({ scene, fps, mapStyleUrl, unavailable, loading, trafficIndex, trafficLoading }: MapCompositionProps) {
  const frame = useCurrentFrame()
  const { width, height } = useVideoConfig()
  const cursorMs = timeForFrame(scene.startMs, frame, fps)
  const projectedCursorMs = Math.floor(cursorMs / MAP_PROJECTION_INTERVAL_MS) * MAP_PROJECTION_INTERVAL_MS
  const mapFrame = useMemo(() => projectMapFrame(scene, projectedCursorMs), [projectedCursorMs, scene])
  const [viewState, setViewState] = useState<MapViewState>(() => ({
    longitude: scene.origin.longitude - (width > 760 ? 24 : 0), latitude: Math.max(-55, Math.min(55, scene.origin.latitude - 16)),
    zoom: width > 760 ? 1.55 : 1.4, minZoom: -1, maxZoom: 16, pitch: 28, bearing: 0,
  }))
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [activeOnly, setActiveOnly] = useState(false)
  const [showTraffic, setShowTraffic] = useState(true)
  const [reducedMotion, setReducedMotion] = useState(false)
  const [mapError, setMapError] = useState(false)
  const selected = mapFrame.points.find((point) => point.id === selectedId)
  const selection = selected ? selectedId : null
  const visiblePoints = useMemo(() => activeOnly ? mapFrame.points.filter((point) => point.activeFlowCount > 0) : mapFrame.points, [activeOnly, mapFrame.points])
  const routes = useMemo(() => bundleMapArcs(activeOnly ? mapFrame.arcs.filter((arc) => arc.activeFlowCount > 0) : mapFrame.arcs), [activeOnly, mapFrame.arcs])
  const trafficAnchorMs = Math.floor(cursorMs / TRAFFIC_BUCKET_MS) * TRAFFIC_BUCKET_MS
  const trafficProfiles = useMemo(() => projectTrafficProfiles(scene, trafficIndex, trafficAnchorMs), [scene, trafficIndex, trafficAnchorMs])
  const trafficArcs = useMemo(() => volumeArcs(routes, trafficProfiles), [routes, trafficProfiles])
  const estimatedTraffic = Array.from(trafficProfiles.values()).some((profile) => profile.source === 'estimated')
  const partialTraffic = Array.from(trafficProfiles.values()).some((profile) => profile.source === 'partial')
  const selectedTraffic = selection ? trafficProfiles.get(selection) : undefined
  const topPoints = useMemo(() => [...visiblePoints].sort((a, b) => b.bytes - a.bytes || a.ip.localeCompare(b.ip)).slice(0, 5), [visiblePoints])
  const origin = useMemo(() => [{ position: [scene.origin.longitude, scene.origin.latitude] as MapPosition, label: scene.origin.label }], [scene.origin])
  const countries = useMemo(() => {
    const seen = new Set(mapFrame.points.map((point) => point.id))
    return new Set(scene.endpoints.filter((endpoint) => seen.has(endpoint.id)).map((endpoint) => endpoint.country).filter(Boolean)).size
  }, [mapFrame.points, scene.endpoints])
  const [volumeValue, volumeUnit] = formatBytes(mapFrame.byteCount).split(' ')

  useEffect(() => {
    const query = window.matchMedia('(prefers-reduced-motion: reduce)')
    const update = () => setReducedMotion(query.matches)
    update()
    query.addEventListener('change', update)
    return () => query.removeEventListener('change', update)
  }, [])

  const layers = useMemo(() => {
    const routeOpacity = (arc: BundledMapArc) => !selection || arc.endpointIds.includes(selection) ? 1 : 0.12
    const arcProps = {
      data: routes, greatCircle: true, wrapLongitude: true, numSegments: 160,
      getSourcePosition: (arc: BundledMapArc) => arc.sourcePosition,
      getTargetPosition: (arc: BundledMapArc) => arc.targetPosition,
      getHeight: 0.18, getTilt: (arc: BundledMapArc) => arc.tilt,
      visible: showTraffic, parameters: { depthCompare: 'always' as const, depthWriteEnabled: false },
      updateTriggers: { getSourceColor: selection, getTargetColor: selection },
    }
    return [
      new PathLayer<MapPosition[]>({
        id: 'atlas-grid', data: GRATICULE, getPath: (path) => path,
        getColor: [69, 102, 118, 27], getWidth: 1, widthUnits: 'pixels', pickable: false,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, id: 'route-glow',
        getSourceColor: (arc) => [88, 222, 192, 10 * routeOpacity(arc)],
        getTargetColor: (arc) => [115, 170, 235, 8 * routeOpacity(arc)], getWidth: 3,
      }),
      new ArcLayer<BundledMapArc>({
        ...arcProps, id: 'connection-strips', getWidth: 1,
        getSourceColor: (arc) => [88, 222, 192, 95 * routeOpacity(arc)],
        getTargetColor: (arc) => [115, 170, 235, 70 * routeOpacity(arc)],
      }),
      new FlowArcLayer<TrafficArc>({
        ...arcProps, data: trafficArcs, id: 'traffic-streams', time: frame / fps, motion: reducedMotion ? 0 : 1,
        phase: (cursorMs - trafficAnchorMs) / TRAFFIC_BUCKET_MS,
        getRadii0: (arc) => arc.radii.slice(0, 4), getRadii1: (arc) => arc.radii.slice(4, 8), getRadii2: (arc) => arc.radii.slice(8, 12),
        getSourceColor: (arc) => alpha(TEAL, routeOpacity(arc)),
        getTargetColor: (arc) => alpha(BLUE, routeOpacity(arc)),
        parameters: { depthCompare: 'less-equal', depthWriteEnabled: true },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destination-halos', data: visiblePoints, getPosition: (point) => point.position,
        radiusUnits: 'pixels', getRadius: (point) => point.id === selection ? 17 : 10,
        getFillColor: (point) => point.activeFlowCount > 0 ? [92, 216, 191, 14] : [118, 147, 165, 7],
        updateTriggers: { getRadius: selection }, parameters: { depthCompare: 'always' },
      }),
      new ScatterplotLayer<MapPoint>({
        id: 'destinations', data: visiblePoints, pickable: true, radiusUnits: 'pixels', stroked: true,
        getPosition: (point) => point.position, getRadius: (point) => point.id === selection ? 5.5 : 3.5,
        getFillColor: (point) => point.activeFlowCount > 0 ? TEAL : [111, 141, 159, 200],
        getLineColor: (point) => point.id === selection ? [230, 255, 248, 255] : [11, 24, 34, 230],
        getLineWidth: 1.5, lineWidthUnits: 'pixels',
        updateTriggers: { getRadius: selection, getLineColor: selection }, parameters: { depthCompare: 'always' },
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
  }, [cursorMs, fps, frame, routes, origin, reducedMotion, selection, showTraffic, trafficAnchorMs, trafficArcs, visiblePoints])

  function moveTo(next: Partial<MapViewState>) {
    setViewState((current) => ({ ...current, ...next, transitionDuration: reducedMotion ? 0 : 700, transitionInterpolator: new FlyToInterpolator() }))
  }

  function fitNetwork() {
    const positions = [origin[0].position, ...visiblePoints.map((point) => point.position)]
    // Unwrap around the gateway so dateline routes take the short way around.
    const longitudes = positions.map(([lon]) => scene.origin.longitude + ((lon - scene.origin.longitude + 540) % 360) - 180)
    const latitudes = positions.map(([, lat]) => Math.max(-80, Math.min(80, lat)))
    const viewport = new WebMercatorViewport({ width, height }).fitBounds([
      [Math.min(...longitudes), Math.min(...latitudes)], [Math.max(...longitudes), Math.max(...latitudes)],
    ], { padding: width > 760 ? { left: 340, right: 100, top: 100, bottom: 100 } : 65, maxZoom: 6 })
    moveTo({ longitude: viewport.longitude, latitude: viewport.latitude, zoom: viewport.zoom, pitch: 0, bearing: 0 })
  }

  function selectPoint(point: MapPoint) {
    setSelectedId(point.id)
    moveTo({ longitude: point.position[0], latitude: point.position[1], zoom: Math.max(3.5, Math.min(viewState.zoom, 6)) })
  }

  return (
    <AbsoluteFill className="atlas-composition" data-map-zoom={viewState.zoom.toFixed(2)} data-map-pitch={viewState.pitch}>
      <DeckGL
        controller={{ dragRotate: true, touchRotate: true }} viewState={viewState}
        onViewStateChange={({ viewState: next }) => setViewState(next as MapViewState)}
        layers={layers} getTooltip={tooltipForPoint}
        onClick={({ object, layer }) => { if (layer?.id === 'destinations' && object) selectPoint(object as MapPoint) }}
        getCursor={({ isDragging, isHovering }) => isDragging ? 'grabbing' : isHovering ? 'pointer' : 'grab'}
      >
        <Map reuseMaps mapStyle={mapStyleUrl} minZoom={-1} attributionControl={{ compact: true }}
          onError={() => setMapError(true)} onIdle={() => setMapError(false)} />
      </DeckGL>
      <div className="atlas-vignette" />

      <aside className="atlas-overview" aria-label="Traffic overview">
        <div className="atlas-eyebrow"><span className="atlas-tiny-line" /> SESSION INTELLIGENCE</div>
        <h1>Traffic overview</h1>
        <p className="atlas-subtitle">Your network, in perspective.</p>
        <div className="atlas-metrics">
          <div><span className="atlas-metric-value atlas-accent">{mapFrame.activeFlowCount.toLocaleString()}</span><span className="atlas-metric-label"><i className="atlas-dot" />Active flows</span></div>
          <div><span className="atlas-metric-value">{mapFrame.points.length.toLocaleString()}</span><span className="atlas-metric-label">Destinations</span></div>
          <div><span className="atlas-metric-value atlas-metric-bytes">{volumeValue}<small>{volumeUnit}</small></span><span className="atlas-metric-label">Observed volume</span></div>
          <div><span className="atlas-metric-value">{countries}</span><span className="atlas-metric-label">Countries</span></div>
        </div>
        <section className="atlas-destinations">
          <div className="atlas-section-heading"><h2>Top destinations</h2><span>BY VOLUME</span></div>
          <div className="atlas-segmented" aria-label="Destination filter">
            <button type="button" aria-pressed={!activeOnly} onClick={() => setActiveOnly(false)}>All observed</button>
            <button type="button" aria-pressed={activeOnly} onClick={() => setActiveOnly(true)}>Active now</button>
          </div>
          <div className="atlas-destination-list">
            {topPoints.map((point, index) => (
              <button type="button" className={`atlas-destination ${selection === point.id ? 'is-selected' : ''}`} key={point.id} onClick={() => selectPoint(point)} aria-pressed={selection === point.id}>
                <span className="atlas-rank">{String(index + 1).padStart(2, '0')}</span>
                <span className="atlas-destination-content"><span className="atlas-destination-name">{point.provider || point.label}</span><span className="atlas-destination-location">{point.location || point.ip}</span><span className="atlas-volume-track"><span style={{ width: `${point.bytes / Math.max(1, topPoints[0]?.bytes ?? 1) * 100}%` }} /></span></span>
                <span className="atlas-destination-volume">{formatBytes(point.bytes)}<MapIcon name="arrow" size={13} /></span>
              </button>
            ))}
            {topPoints.length === 0 && <p className="atlas-list-empty">{activeOnly ? 'No active destinations at this moment.' : 'Destinations appear as traffic is observed.'}</p>}
          </div>
        </section>
        <div className="atlas-origin"><span className="atlas-origin-icon"><MapIcon name="target" size={17} /></span><div><span>OBSERVATION POINT</span><strong>{scene.origin.label}</strong><small>{Math.abs(scene.origin.latitude).toFixed(2)}° {scene.origin.latitude < 0 ? 'S' : 'N'} · {Math.abs(scene.origin.longitude).toFixed(2)}° {scene.origin.longitude < 0 ? 'W' : 'E'}</small></div></div>
      </aside>

      <div className="atlas-map-heading"><MapIcon name="globe" size={15} /><span>NETWORK ATLAS</span><i /><span className="atlas-map-heading-detail">Geographic view</span></div>
      <div className="atlas-view-options">
        <div className="atlas-segmented atlas-view-switch" aria-label="Map perspective">
          <button type="button" aria-pressed={viewState.pitch !== 0} onClick={() => moveTo({ pitch: 35 })}>Perspective</button>
          <button type="button" aria-pressed={viewState.pitch === 0} onClick={() => moveTo({ pitch: 0, bearing: 0 })}>Top-down</button>
        </div>
        <button type="button" className="atlas-layer-button" aria-pressed={showTraffic} onClick={() => setShowTraffic((value) => !value)} title="Toggle traffic routes"><MapIcon name="layers" size={16} /><span>Traffic</span><i className="atlas-dot" /></button>
      </div>

      {selected && <section className="atlas-selection" aria-label="Selected destination">
        <div className="atlas-section-heading"><span><i className={`atlas-dot ${selected.activeFlowCount ? '' : 'is-muted'}`} /> {selected.activeFlowCount ? 'ACTIVE DESTINATION' : 'OBSERVED DESTINATION'}</span><button type="button" className="atlas-icon-button" onClick={() => setSelectedId(null)} aria-label="Close destination details"><MapIcon name="close" size={16} /></button></div>
        <h2>{selected.provider || selected.label}</h2><p>{selected.label}</p><div className="atlas-selection-location"><MapIcon name="pin" size={14} />{selected.location || 'Location unknown'}</div>
        <dl><div><dt>IP address</dt><dd>{selected.ip}</dd></div><div><dt>Observed volume</dt><dd>{formatBytes(selected.bytes)}</dd></div><div><dt>{selectedTraffic?.source === 'estimated' ? 'Average rate (estimated)' : 'Recent payload rate'}</dt><dd>{selectedTraffic && selectedTraffic.source !== 'unavailable' ? `${formatBytes(selectedTraffic.rates[0])}/s` : 'Unavailable'}</dd></div><div><dt>Flows seen / active</dt><dd>{selected.flowCount} / {selected.activeFlowCount}</dd></div></dl>
      </section>}

      {scene.endpoints.length === 0 && <div className="atlas-empty"><MapIcon name="globe" size={30} /><h2>{unavailable ? 'Session data unavailable' : loading ? 'Connecting to your session' : 'No mapped destinations yet'}</h2><p>{unavailable ? 'Check the gateway connection and try again.' : loading ? 'Loading the network view…' : 'Geolocated traffic will appear here as it is observed.'}</p></div>}
      {mapError && <div className="atlas-map-error" role="status">Basemap tiles are unavailable. Traffic is still shown.</div>}

      <div className="atlas-map-tools" aria-label="Map controls">
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.min(16, viewState.zoom + 1) })} aria-label="Zoom in" title="Zoom in"><MapIcon name="plus" /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ zoom: Math.max(-1, viewState.zoom - 1) })} aria-label="Zoom out" title="Zoom out"><MapIcon name="minus" /></button>
        <span />
        <button type="button" className="atlas-icon-button" onClick={fitNetwork} aria-label="Fit network" title="Fit network"><MapIcon name="expand" size={17} /></button>
        <button type="button" className="atlas-icon-button" onClick={() => moveTo({ longitude: scene.origin.longitude, latitude: scene.origin.latitude, zoom: 5, bearing: 0 })} aria-label="Center on gateway" title="Center on gateway"><MapIcon name="target" /></button>
      </div>
      <div className="atlas-map-footer"><div className="atlas-legend"><span><i className="atlas-route-swatch" />Connection</span><span><i className="atlas-volume-swatch" />Traffic volume</span><span><i className="atlas-gateway-swatch" />Gateway</span></div><p className="atlas-traffic-scale" data-traffic-source={estimatedTraffic ? 'estimated' : partialTraffic ? 'partial' : 'sampled'}>Bulge size = traffic / second{trafficLoading ? ' · Loading samples' : estimatedTraffic ? ' · Estimated averages where samples are unavailable' : partialTraffic ? ' · Partial measurements' : ''}</p><p>Approximate routes · Coarse IP locations</p></div>
    </AbsoluteFill>
  )
}

function alpha(color: Color, opacity: number): Color {
  return [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)]
}

function tooltipForPoint({ object, layer }: PickingInfo<MapPoint>) {
  if (!object || layer?.id !== 'destinations') return null
  return {
    text: [object.label, object.location, object.ip, `${object.flowCount.toLocaleString()} flows · ${formatBytes(object.bytes)}`, 'Click to inspect destination'].filter(Boolean).join('\n'),
    style: { backgroundColor: '#11232e', color: '#e1eeed', fontSize: '12px', lineHeight: '1.7', border: '1px solid #30464f', borderRadius: '8px', padding: '12px 16px' },
  }
}
