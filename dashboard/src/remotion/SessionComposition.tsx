import { useMemo } from 'react'
import { useCurrentFrame } from 'remotion'
import { buildTreemap } from '../model/treemap'
import type { SessionComposition as SessionCompositionModel } from '../model/sessionModel'
import { formatBytes, formatClock, formatDuration } from '../views/formatters'

export type DashboardViewMode = 'timeline' | 'treemap'

export type SessionCompositionProps = {
  composition: SessionCompositionModel
  viewMode: DashboardViewMode
  zoomFrames: number | 'all'
  selectedClipId: string | null
  selectedServiceId: string | null
  followLive: boolean
}

const palette = [
  '#2563eb',
  '#059669',
  '#dc2626',
  '#7c3aed',
  '#d97706',
  '#0891b2',
  '#be123c',
  '#4f46e5',
  '#65a30d',
  '#9333ea',
]

export function SessionComposition({
  composition,
  viewMode,
  zoomFrames,
  selectedClipId,
  selectedServiceId,
  followLive,
}: SessionCompositionProps) {
  const frame = useCurrentFrame()
  const visibleRange = getVisibleRange(frame, composition.durationInFrames, zoomFrames, followLive)

  return (
    <div className="h-full w-full bg-[#f8fafc] text-slate-950">
      {viewMode === 'timeline' ? (
        <TimelineScene
          composition={composition}
          currentFrame={frame}
          visibleStartFrame={visibleRange.start}
          visibleEndFrame={visibleRange.end}
          selectedClipId={selectedClipId}
          selectedServiceId={selectedServiceId}
        />
      ) : (
        <TreemapScene
          composition={composition}
          currentFrame={frame}
          selectedServiceId={selectedServiceId}
        />
      )}
    </div>
  )
}

function TimelineScene({
  composition,
  currentFrame,
  visibleStartFrame,
  visibleEndFrame,
  selectedClipId,
  selectedServiceId,
}: {
  composition: SessionCompositionModel
  currentFrame: number
  visibleStartFrame: number
  visibleEndFrame: number
  selectedClipId: string | null
  selectedServiceId: string | null
}) {
  const frameSpan = Math.max(1, visibleEndFrame - visibleStartFrame)
  const lanes = composition.lanes
  const availableLaneHeight = composition.height - 118
  const laneHeight = Math.max(12, Math.min(46, availableLaneHeight / Math.max(1, lanes.length)))
  const leftAxis = 252
  const timelineWidth = composition.width - leftAxis - 34
  const playheadX = leftAxis + ((currentFrame - visibleStartFrame) / frameSpan) * timelineWidth
  const marks = buildTimeMarks(visibleStartFrame, visibleEndFrame, composition.sessionStartMs, composition.fps)

  return (
    <div className="relative h-full overflow-hidden">
      <div className="absolute inset-x-0 top-0 flex h-[70px] items-center justify-between border-b border-slate-200 bg-white px-8">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Session timeline</div>
          <div className="mt-1 text-2xl font-semibold text-slate-950">
            {formatClock(frameToMs(currentFrame, composition))}
          </div>
        </div>
        <div className="flex items-center gap-5 text-sm text-slate-600">
          <span>{composition.totals.flowCount} flows</span>
          <span>{formatTraffic(composition.totals.byteCount, composition.totals.trafficCountersAvailable)}</span>
          <span>{formatDuration((visibleEndFrame - visibleStartFrame) / composition.fps)} window</span>
        </div>
      </div>

      <div className="absolute left-0 right-0 top-[70px] h-12 border-b border-slate-200 bg-slate-50">
        <div className="absolute bottom-0 left-0 top-0 w-[252px] border-r border-slate-200 bg-white px-8 py-3 text-xs font-semibold uppercase text-slate-500">
          Site / app
        </div>
        {marks.map((mark) => (
          <div
            className="absolute top-0 h-full border-l border-slate-200 px-2 pt-3 text-xs text-slate-500"
            key={mark.frame}
            style={{ left: leftAxis + mark.x * timelineWidth }}
          >
            {mark.label}
          </div>
        ))}
      </div>

      <div className="absolute inset-x-0 bottom-0 top-[118px]">
        {lanes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-lg font-medium text-slate-500">
            Waiting for flow observations.
          </div>
        ) : (
          lanes.map((lane, laneIndex) => {
            const top = laneIndex * laneHeight
            const selected = selectedServiceId === lane.serviceGroupId
            return (
              <div
                className={`absolute left-0 right-0 border-b border-slate-100 ${selected ? 'bg-sky-50' : 'bg-white'}`}
                key={lane.id}
                style={{ top, height: laneHeight }}
              >
                <button
                  className="absolute bottom-0 left-0 top-0 flex w-[252px] items-center border-r border-slate-200 bg-transparent px-8 text-left"
                  onClick={() => dispatchSelection('service', lane.serviceGroupId)}
                  type="button"
                >
                  <span className="min-w-0">
                    <span className="block truncate text-sm font-semibold leading-tight text-slate-900">{lane.label}</span>
                    {laneHeight >= 28 ? (
                      <span className="block truncate text-xs text-slate-500">
                        {formatTraffic(lane.totalBytes, composition.totals.trafficCountersAvailable)}
                      </span>
                    ) : null}
                  </span>
                </button>
                <div className="absolute bottom-0 right-[34px] top-0" style={{ left: leftAxis }}>
                  {lane.clips.map((clip) => {
                    const start = Math.max(clip.startFrame, visibleStartFrame)
                    const end = Math.min(clip.startFrame + clip.durationFrames, visibleEndFrame)
                    if (end < visibleStartFrame || start > visibleEndFrame) {
                      return null
                    }

                    const active = currentFrame >= clip.startFrame && currentFrame <= clip.startFrame + clip.durationFrames
                    const selectedClip = selectedClipId === clip.id
                    const x = ((start - visibleStartFrame) / frameSpan) * timelineWidth
                    const width = Math.max(4, ((end - start) / frameSpan) * timelineWidth)
                    const color = colorForService(clip.serviceGroupId)

                    return (
                      <button
                        className={`absolute overflow-hidden rounded-sm border text-left shadow-sm transition ${
                          selectedClip ? 'border-slate-950 ring-2 ring-slate-950' : 'border-white'
                        } ${active ? 'opacity-100' : 'opacity-75'}`}
                        key={clip.id}
                        onClick={() => dispatchSelection('clip', clip.id)}
                        style={{
                          left: x,
                          top: Math.max(2, (laneHeight - Math.min(28, laneHeight - 4)) / 2),
                          width,
                          height: Math.max(6, Math.min(28, laneHeight - 4)),
                          backgroundColor: color,
                        }}
                        title={`${clip.label} / ${formatTraffic(clip.bytes, composition.totals.trafficCountersAvailable)}`}
                        type="button"
                      >
                        {laneHeight >= 18 ? (
                          <span className="block truncate px-2 text-xs font-semibold text-white">
                            {clip.label}
                          </span>
                        ) : null}
                      </button>
                    )
                  })}
                </div>
              </div>
            )
          })
        )}
      </div>

      <div
        className="absolute bottom-0 top-[70px] z-20 w-px bg-red-600"
        style={{ left: Math.max(leftAxis, Math.min(leftAxis + timelineWidth, playheadX)) }}
      >
        <div className="-ml-[5px] h-3 w-3 rounded-full bg-red-600" />
      </div>
      <div className="absolute bottom-5 right-7 rounded-sm bg-white/90 px-3 py-2 text-xs font-medium text-slate-600 shadow-sm">
        Lanes group observed requests into site and app activity sections.
      </div>
    </div>
  )
}

function TreemapScene({
  composition,
  currentFrame,
  selectedServiceId,
}: {
  composition: SessionCompositionModel
  currentFrame: number
  selectedServiceId: string | null
}) {
  const activeGroups = useMemo(() => {
    const active = new Set(
      composition.clips
        .filter((clip) => clip.startFrame <= currentFrame)
        .map((clip) => clip.serviceGroupId),
    )
    return composition.serviceGroups.filter((group) => active.has(group.id))
  }, [composition, currentFrame])
  const nodes = buildTreemap(activeGroups.length ? activeGroups : composition.serviceGroups, 1320, 610)
  const areaMetric = composition.totals.trafficCountersAvailable ? 'observed bytes' : 'flow count'

  return (
    <div className="relative h-full overflow-hidden bg-white">
      <div className="flex h-[82px] items-center justify-between border-b border-slate-200 px-8">
        <div>
          <div className="text-xs font-semibold uppercase tracking-wide text-slate-500">Activity treemap</div>
          <div className="mt-1 text-2xl font-semibold text-slate-950">
            {activeGroups.length} site/app groups observed by {formatClock(frameToMs(currentFrame, composition))}
          </div>
        </div>
        <div className="text-sm text-slate-600">Area represents {areaMetric}.</div>
      </div>

      <div className="absolute left-[60px] top-[128px] h-[610px] w-[1320px]">
        {nodes.length === 0 ? (
          <div className="flex h-full items-center justify-center border border-dashed border-slate-300 text-lg font-medium text-slate-500">
            Waiting for activity observations.
          </div>
        ) : (
          nodes.map((node) => {
            const selected = selectedServiceId === node.group.id
            return (
              <button
                className={`absolute overflow-hidden rounded-sm border-2 p-3 text-left transition ${
                  selected ? 'border-slate-950' : 'border-white'
                }`}
                key={node.group.id}
                onClick={() => dispatchSelection('service', node.group.id)}
                style={{
                  left: node.x,
                  top: node.y,
                  width: node.width,
                  height: node.height,
                  backgroundColor: colorForService(node.group.id),
                }}
                type="button"
              >
                <span className="block truncate text-lg font-semibold text-white">{node.group.label}</span>
                <span className="mt-1 block text-sm font-medium text-white/85">
                  {formatTraffic(node.group.totalBytes, composition.totals.trafficCountersAvailable)} / {node.group.flowCount} flows
                </span>
                {node.width > 240 && node.height > 120 ? (
                  <span className="mt-4 block text-sm text-white/80">
                    {node.group.providerLabel || node.group.sourceSignal} · {node.group.confidence}
                  </span>
                ) : null}
              </button>
            )
          })
        )}
      </div>
    </div>
  )
}

function getVisibleRange(
  frame: number,
  durationInFrames: number,
  zoomFrames: number | 'all',
  followLive: boolean,
) {
  if (zoomFrames === 'all' || zoomFrames >= durationInFrames) {
    return { start: 0, end: durationInFrames }
  }

  const anchor = followLive ? durationInFrames : frame
  const start = Math.max(0, Math.min(anchor - zoomFrames * 0.82, durationInFrames - zoomFrames))
  return {
    start,
    end: Math.min(durationInFrames, start + zoomFrames),
  }
}

function buildTimeMarks(startFrame: number, endFrame: number, sessionStartMs: number, fps: number) {
  const span = Math.max(1, endFrame - startFrame)
  return Array.from({ length: 7 }, (_, index) => {
    const frame = startFrame + (span / 6) * index
    return {
      frame,
      x: (frame - startFrame) / span,
      label: formatClock(sessionStartMs + (frame / fps) * 1000),
    }
  })
}

function frameToMs(frame: number, composition: SessionCompositionModel) {
  return composition.sessionStartMs + (frame / composition.fps) * 1000
}

function formatTraffic(bytes: number, countersAvailable: boolean) {
  return countersAvailable ? formatBytes(bytes) : 'Counters unavailable'
}

function colorForService(serviceId: string) {
  let hash = 0
  for (let index = 0; index < serviceId.length; index += 1) {
    hash = (hash * 31 + serviceId.charCodeAt(index)) >>> 0
  }
  return palette[hash % palette.length]
}

function dispatchSelection(kind: 'clip' | 'service', id: string) {
  if (typeof window === 'undefined') {
    return
  }
  window.dispatchEvent(new CustomEvent('infrareveal:select', { detail: { kind, id } }))
}
