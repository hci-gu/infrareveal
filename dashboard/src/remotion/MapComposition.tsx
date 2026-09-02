import type { Color, PickingInfo } from '@deck.gl/core'
import { ArcLayer, ScatterplotLayer } from '@deck.gl/layers'
import DeckGL from '@deck.gl/react'
import { useMemo } from 'react'
import Map from 'react-map-gl/maplibre'
import { AbsoluteFill, useCurrentFrame } from 'remotion'
import { timeForFrame } from '@infrareveal/session-state'
import type { ConnectionState, PlaybackState } from '@infrareveal/session-state'
import type { MapArc, MapPoint, MapTimelineScene } from '../map/mapModel'
import { projectMapFrame } from '../map/mapModel'

export type MapCompositionProps = {
  scene: MapTimelineScene
  fps: number
  connectionState: ConnectionState
  timelineMode: 'live' | 'recorded'
  playbackState: PlaybackState
  mapStyleUrl: string
}

const MAP_PROJECTION_INTERVAL_MS = 250
const SOURCE_COLOR: Color = [167, 29, 49, 230]
const TARGET_COLOR: Color = [245, 137, 22, 230]

export function MapComposition({
  scene,
  fps,
  connectionState,
  timelineMode,
  playbackState,
  mapStyleUrl,
}: MapCompositionProps) {
  const frame = useCurrentFrame()
  const cursorMs = timeForFrame(scene.startMs, frame, fps)
  const projectedCursorMs = Math.floor(cursorMs / MAP_PROJECTION_INTERVAL_MS) * MAP_PROJECTION_INTERVAL_MS
  const mapFrame = useMemo(
    () => projectMapFrame(scene, projectedCursorMs),
    [projectedCursorMs, scene],
  )
  const pulse = 0.82 + Math.sin(frame / 4) * 0.18
  const layers = useMemo(() => [
    new ArcLayer<MapArc>({
      id: 'active-flow-arcs',
      data: mapFrame.arcs,
      pickable: false,
      greatCircle: true,
      getSourcePosition: (arc) => arc.sourcePosition,
      getTargetPosition: (arc) => arc.targetPosition,
      getSourceColor: () => withAlpha(SOURCE_COLOR, pulse),
      getTargetColor: () => withAlpha(TARGET_COLOR, pulse),
      getWidth: (arc) => Math.min(7, 1.4 + Math.log10(arc.bytes + 10) + Math.log2(arc.activeFlowCount + 1)),
      getHeight: 0.35,
      getTilt: (arc) => arc.tilt,
      updateTriggers: {
        getSourceColor: frame,
        getTargetColor: frame,
      },
      widthMinPixels: 1.5,
      widthMaxPixels: 8,
    }),
    new ScatterplotLayer<MapPoint>({
      id: 'destinations',
      data: mapFrame.points,
      pickable: true,
      radiusUnits: 'pixels',
      stroked: true,
      filled: true,
      getPosition: (point) => point.position,
      getRadius: (point) => Math.min(20, 4 + Math.log10(point.bytes + 10) * 2),
      getFillColor: (point) => point.activeFlowCount > 0 ? [167, 29, 49, 210] : [84, 94, 110, 155],
      getLineColor: [255, 255, 255, 215],
      getLineWidth: 1,
      lineWidthUnits: 'pixels',
      radiusMinPixels: 4,
      radiusMaxPixels: 20,
    }),
    new ScatterplotLayer<{ position: [number, number] }>({
      id: 'gateway-origin',
      data: [{ position: [scene.origin.longitude, scene.origin.latitude] }],
      pickable: false,
      radiusUnits: 'pixels',
      stroked: true,
      filled: true,
      getPosition: (point) => point.position,
      getRadius: 8,
      getFillColor: [167, 29, 49, 255],
      getLineColor: [255, 255, 255, 255],
      getLineWidth: 2,
      lineWidthUnits: 'pixels',
    }),
  ], [frame, mapFrame.arcs, mapFrame.points, pulse, scene.origin.latitude, scene.origin.longitude])

  return (
    <AbsoluteFill className="overflow-hidden bg-[#e8edf1] text-slate-950">
      <DeckGL
        controller
        initialViewState={{
          longitude: scene.origin.longitude,
          latitude: scene.origin.latitude,
          zoom: 1.5,
          minZoom: 0,
          maxZoom: 16,
          pitch: 36,
          bearing: 0,
        }}
        layers={layers}
        getTooltip={tooltipForPoint}
      >
        <Map
          reuseMaps
          mapStyle={mapStyleUrl}
          attributionControl={{ compact: true }}
        />
      </DeckGL>

      <div className="pointer-events-none absolute left-7 top-7 min-w-[330px] border border-white/75 bg-white/90 px-5 py-4 shadow-lg backdrop-blur-sm">
        <div className="flex items-center justify-between gap-5">
          <div>
            <div className="text-[11px] font-semibold uppercase tracking-[0.18em] text-slate-500">
              Network destinations
            </div>
            <h1 className="mt-1 max-w-[460px] truncate text-2xl font-semibold tracking-tight text-slate-950">
              {scene.sessionName}
            </h1>
          </div>
          <StatusBadge mode={timelineMode} connectionState={connectionState} playbackState={playbackState} />
        </div>
        <div className="mt-4 grid grid-cols-3 gap-5 border-t border-slate-200 pt-3">
          <Metric label="Destinations" value={mapFrame.points.length} />
          <Metric label="Flows seen" value={mapFrame.seenFlowCount} />
          <Metric label="Active" value={mapFrame.activeFlowCount} accent />
        </div>
      </div>

      <div className="pointer-events-none absolute right-7 top-7 bg-slate-950/80 px-4 py-3 text-right text-white shadow-lg backdrop-blur-sm">
        <div className="font-mono text-lg font-semibold tabular-nums">{formatCursor(cursorMs)}</div>
        <div className="mt-0.5 text-[10px] font-semibold uppercase tracking-[0.16em] text-slate-300">
          {formatBytes(mapFrame.byteCount)} observed
        </div>
      </div>

      {scene.endpoints.length === 0 && (
        <div className="pointer-events-none absolute inset-0 flex items-center justify-center">
          <div className="border border-slate-200 bg-white/90 px-6 py-5 text-center shadow-lg backdrop-blur-sm">
            <div className="text-sm font-semibold text-slate-900">Waiting for geolocated destinations</div>
            <div className="mt-1 text-xs text-slate-500">The map updates as the shared session state receives flows and destination metadata.</div>
          </div>
        </div>
      )}

      <div className="pointer-events-none absolute bottom-16 left-7 flex items-center gap-4 bg-white/90 px-3 py-2 text-[10px] font-semibold uppercase tracking-wider text-slate-600 shadow backdrop-blur-sm">
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-[#a71d31]" /> Active route</span>
        <span className="flex items-center gap-1.5"><i className="h-2.5 w-2.5 rounded-full bg-slate-500" /> Seen destination</span>
      </div>
    </AbsoluteFill>
  )
}

function tooltipForPoint({ object }: PickingInfo<MapPoint>) {
  if (!object) return null
  return {
    text: [
      object.label,
      object.location,
      object.ip,
      `${object.flowCount.toLocaleString()} flows · ${formatBytes(object.bytes)}`,
    ].filter(Boolean).join('\n'),
  }
}

function StatusBadge({
  mode,
  connectionState,
  playbackState,
}: {
  mode: 'live' | 'recorded'
  connectionState: ConnectionState
  playbackState: PlaybackState
}) {
  const live = mode === 'live'
  const unavailable = connectionState === 'error' || connectionState === 'offline'
  const behindLive = live && playbackState !== 'following'
  const degraded = live && connectionState !== 'live'
  const label = unavailable
    ? connectionState
    : behindLive
      ? 'Behind live'
      : degraded
        ? connectionState
        : live
          ? 'Live'
          : 'Recorded'
  return (
    <div className={`flex items-center gap-2 px-2.5 py-1.5 text-[10px] font-bold uppercase tracking-[0.14em] ${
      unavailable || behindLive || degraded
        ? 'bg-amber-100 text-amber-900'
        : live
          ? 'bg-[#a71d31] text-white'
          : 'bg-slate-200 text-slate-700'
    }`}>
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {label}
    </div>
  )
}

function Metric({ label, value, accent = false }: { label: string; value: number; accent?: boolean }) {
  return (
    <div>
      <div className={`text-xl font-semibold tabular-nums ${accent ? 'text-[#a71d31]' : 'text-slate-950'}`}>
        {value.toLocaleString()}
      </div>
      <div className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">{label}</div>
    </div>
  )
}

function withAlpha(color: Color, opacity: number): Color {
  return [color[0], color[1], color[2], Math.round((color[3] ?? 255) * opacity)]
}

function formatCursor(cursorMs: number) {
  if (!Number.isFinite(cursorMs) || cursorMs <= 0) return '--:--:-- UTC'
  return `${new Intl.DateTimeFormat('en-GB', {
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hourCycle: 'h23',
    timeZone: 'UTC',
  }).format(cursorMs)} UTC`
}

function formatBytes(bytes: number) {
  if (bytes < 1_000) return `${Math.round(bytes)} B`
  if (bytes < 1_000_000) return `${(bytes / 1_000).toFixed(1)} kB`
  if (bytes < 1_000_000_000) return `${(bytes / 1_000_000).toFixed(1)} MB`
  return `${(bytes / 1_000_000_000).toFixed(1)} GB`
}
