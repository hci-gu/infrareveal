import { useMemo } from 'react'
import { useCurrentFrame } from 'remotion'
import { buildTreemap } from '../model/treemap'
import { activityVisualMetrics, resolveTimelineViewport } from '../model/timelineViewport'
import type { SceneActivityColumn, SceneWindow } from '../timeline/selectors/selectSceneWindow'
import { formatBytes, formatClock, formatDuration } from '../views/formatters'

export type DashboardViewMode = 'timeline' | 'treemap'

export type { SceneWindow } from '../timeline/selectors/selectSceneWindow'

export type SessionCompositionProps = {
  sceneWindow: SceneWindow
  viewMode: DashboardViewMode
  zoomFrames: number | 'all'
  selectedClipId: string | null
  selectedServiceId: string | null
  focusedServiceId: string | null
  collapsedServiceIds: string[]
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
const MAX_RENDERED_LANES = 160
const MAX_RENDERED_CLIPS_PER_LANE = 240

export function SessionComposition({
  sceneWindow: composition,
  viewMode,
  zoomFrames,
  selectedClipId,
  selectedServiceId,
  focusedServiceId,
  collapsedServiceIds,
  followLive,
}: SessionCompositionProps) {
  const frame = useCurrentFrame()
  const focusedLane = composition.lanes.find((lane) => lane.serviceGroupId === focusedServiceId)
  const focusBounds = focusedLane
    ? {
        start: Math.min(...focusedLane.clips.map((clip) => clip.startFrame)),
        end: Math.max(...focusedLane.clips.map((clip) => clip.startFrame + clip.durationFrames)),
      }
    : null
  const visibleRange = resolveTimelineViewport({
    currentFrame: frame,
    durationInFrames: composition.durationInFrames,
    focusBounds,
    followLive,
    zoomFrames,
  })

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
          focusedServiceId={focusedServiceId}
          collapsedServiceIds={collapsedServiceIds}
          overviewOnly={zoomFrames === 'all' && !focusedServiceId}
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
  focusedServiceId,
  collapsedServiceIds,
  overviewOnly,
}: {
  composition: SceneWindow
  currentFrame: number
  visibleStartFrame: number
  visibleEndFrame: number
  selectedClipId: string | null
  selectedServiceId: string | null
  focusedServiceId: string | null
  collapsedServiceIds: string[]
  overviewOnly: boolean
}) {
  const frameSpan = Math.max(1, visibleEndFrame - visibleStartFrame)
  const scopedLanes = focusedServiceId
    ? composition.lanes.filter((lane) => lane.serviceGroupId === focusedServiceId)
    : composition.lanes
  const matchingLanes = scopedLanes.filter((lane) => lane.clips.some((clip) => {
    const clipEnd = clip.startFrame + clip.durationFrames
    return clipEnd >= visibleStartFrame && clip.startFrame <= visibleEndFrame
  }))
  const lanes = matchingLanes.slice(0, MAX_RENDERED_LANES)
  const hiddenLaneCount = Math.max(0, matchingLanes.length - lanes.length)
  const focusedLane = lanes.find((lane) => lane.serviceGroupId === focusedServiceId)
  const domainFocused = Boolean(focusedLane)
  const collapsed = new Set(collapsedServiceIds)
  const leftAxis = 344
  const timelineWidth = composition.width - leftAxis - 34
  const playheadX = leftAxis + ((currentFrame - visibleStartFrame) / frameSpan) * timelineWidth
  const marks = buildTimeMarks(visibleStartFrame, visibleEndFrame, composition.sessionStartMs, composition.fps)

  return (
    <div className="relative h-full overflow-hidden">
      <div className="absolute inset-x-0 top-0 flex h-[70px] items-center justify-between border-b border-slate-200 bg-white px-8">
        <div>
          <div className="flex items-center gap-3 text-xs font-semibold uppercase tracking-wide text-slate-500">
            <span>{domainFocused ? 'Domain activity' : 'Session timeline'}</span>
            {focusedLane ? (
              <button
                className="border border-slate-300 bg-white px-2 py-1 normal-case tracking-normal text-slate-700 hover:bg-slate-50"
                onClick={() => dispatchSelection('clear-focus', focusedLane.serviceGroupId)}
                type="button"
              >
                Show all domains
              </button>
            ) : null}
          </div>
          <div className="mt-1 text-2xl font-semibold text-slate-950">
            {focusedLane ? focusedLane.label : formatClock(frameToMs(currentFrame, composition))}
          </div>
        </div>
        <div className="flex items-center gap-5 text-sm text-slate-600">
          <span className="flex items-center gap-3 text-xs">
            <span className="inline-flex items-center gap-1"><i className="h-2 w-3 bg-amber-500" /> sent</span>
            <span className="inline-flex items-center gap-1"><i className="h-2 w-3 bg-cyan-500" /> received</span>
          </span>
          <span>{composition.totals.flowCount} flows</span>
          <span>{formatTraffic(composition.totals.byteCount, composition.totals.trafficCountersAvailable)}</span>
          <span>{formatDuration((visibleEndFrame - visibleStartFrame) / composition.fps)} window</span>
        </div>
      </div>

      <div className="absolute left-0 right-0 top-[70px] h-12 border-b border-slate-200 bg-slate-50">
        <div className="absolute bottom-0 left-0 top-0 w-[344px] border-r border-slate-200 bg-white px-8 py-3 text-xs font-semibold uppercase text-slate-500">
          Domain / connection
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

      <div className="absolute inset-x-0 bottom-0 top-[118px] overflow-y-auto bg-white">
        {lanes.length === 0 ? (
          <div className="flex h-full items-center justify-center text-lg font-medium text-slate-500">
            Waiting for flow observations.
          </div>
        ) : (
          lanes.map((lane) => {
            const selected = selectedServiceId === lane.serviceGroupId
            const isCollapsed = overviewOnly || collapsed.has(lane.serviceGroupId)
            const matchingClips = lane.clips.filter((clip) => {
              const clipEnd = clip.startFrame + clip.durationFrames
              return clipEnd >= visibleStartFrame && clip.startFrame <= visibleEndFrame
            })
            const visibleClips = matchingClips.slice(0, MAX_RENDERED_CLIPS_PER_LANE)
            const selectedOutsideBudget = matchingClips.find((clip) => clip.id === selectedClipId)
            if (selectedOutsideBudget && !visibleClips.includes(selectedOutsideBudget)) {
              visibleClips[visibleClips.length - 1] = selectedOutsideBudget
            }
            const associatedCount = lane.associatedFlowCount
            const groupStart = Math.max(
              visibleStartFrame,
              Math.min(...lane.clips.map((clip) => clip.startFrame)),
            )
            const groupEnd = Math.min(
              visibleEndFrame,
              Math.max(...lane.clips.map((clip) => clip.startFrame + clip.durationFrames)),
            )
            const groupX = ((groupStart - visibleStartFrame) / frameSpan) * timelineWidth
            const groupWidth = Math.max(4, ((groupEnd - groupStart) / frameSpan) * timelineWidth)
            const color = colorForService(lane.serviceGroupId)

            return (
              <div
                className="relative border-b border-slate-200 bg-white"
                key={lane.id}
              >
                <div className={`sticky top-0 z-10 h-11 border-b border-slate-200 ${selected ? 'bg-sky-100' : 'bg-slate-100'}`}>
                  <button
                    aria-label={`${isCollapsed ? 'Expand' : 'Collapse'} ${lane.label}`}
                    aria-expanded={!isCollapsed}
                    className="absolute bottom-0 left-0 top-0 flex w-11 items-center justify-center border-r border-slate-200 text-slate-600 hover:bg-slate-200"
                    onClick={() => dispatchSelection('toggle-service', lane.serviceGroupId)}
                    title={`${isCollapsed ? 'Expand' : 'Collapse'} ${lane.label}`}
                    type="button"
                  >
                    <span className="text-lg leading-none">{isCollapsed ? '\u25b8' : '\u25be'}</span>
                  </button>
                  <button
                    className="absolute bottom-0 left-11 top-0 flex w-[300px] items-center gap-3 border-r border-slate-200 px-3 text-left hover:bg-slate-200/70"
                    onClick={() => dispatchSelection('focus-service', lane.serviceGroupId)}
                    title={`Focus ${lane.label} and load its full activity history`}
                    type="button"
                  >
                    <span className="min-w-0 flex-1">
                      <span className="block truncate text-sm font-semibold leading-tight text-slate-950">{lane.label}</span>
                      <span className="block truncate text-xs text-slate-500">
                        {lane.flowCount} {lane.flowCount === 1 ? 'connection' : 'connections'}
                        {associatedCount ? ` · ${associatedCount} associated` : ''}
                        {' · '}{formatTraffic(lane.totalBytes, composition.totals.trafficCountersAvailable)}
                      </span>
                    </span>
                  </button>
                  <button
                    aria-label={`Focus ${lane.label}`}
                    className="absolute bottom-0 right-[34px] top-0"
                    onClick={() => dispatchSelection('focus-service', lane.serviceGroupId)}
                    style={{ left: leftAxis }}
                    type="button"
                  >
                    {visibleClips.length ? (
                      <span
                        className="absolute top-[17px] h-2 rounded-full opacity-45"
                        style={{ left: groupX, width: groupWidth, backgroundColor: color }}
                      />
                    ) : null}
                  </button>
                </div>

                {!isCollapsed ? visibleClips.map((clip) => {
                    const start = Math.max(clip.startFrame, visibleStartFrame)
                    const end = Math.min(clip.startFrame + clip.durationFrames, visibleEndFrame)
                    const active = currentFrame >= clip.startFrame && currentFrame <= clip.startFrame + clip.durationFrames
                    const selectedClip = selectedClipId === clip.id
                    const x = ((start - visibleStartFrame) / frameSpan) * timelineWidth
                    const width = Math.max(4, ((end - start) / frameSpan) * timelineWidth)
                    const duration = Math.max(0, (clip.endMs - clip.startMs) / 1000)
                    const activityColumns = clip.activityColumns.filter((sample) => {
                      const sampleFrame = ((sample.startMs - composition.sessionStartMs) / 1000) * composition.fps
                      return sampleFrame >= start && sampleFrame <= end
                    })
                    const activityMetrics = activityVisualMetrics(domainFocused)

                    return (
                      <div
                        className={`relative border-b border-slate-100 ${domainFocused ? 'h-16' : 'h-10'} ${selectedClip ? 'bg-sky-50' : 'bg-white'}`}
                        key={clip.id}
                      >
                        <button
                          className="absolute bottom-0 left-0 top-0 flex w-[344px] items-center border-r border-slate-200 pl-12 pr-3 text-left hover:bg-slate-50"
                          onClick={() => dispatchSelection('clip', clip.id)}
                          type="button"
                        >
                          <span className="mr-3 h-px w-4 shrink-0 bg-slate-300" />
                          <span className="min-w-0">
                            <span className="block truncate text-xs font-semibold text-slate-800">{clip.label}</span>
                            <span className="block truncate font-mono text-[10px] text-slate-500">
                              {clip.protocol.toUpperCase()} · {clip.destinationIP}:{clip.destinationPort} · {formatDuration(duration)}
                              {clip.associationRelationship ? ` · ${associationLabel(clip.associationRelationship)}` : ''}
                            </span>
                          </span>
                        </button>
                        <div className="absolute bottom-0 right-[34px] top-0" style={{ left: leftAxis }}>
                          <button
                            className={`absolute top-1 overflow-hidden rounded-sm border text-left transition ${domainFocused ? 'h-14' : 'h-8'} ${
                              selectedClip ? 'border-slate-950 ring-2 ring-slate-950' : 'border-white'
                            } ${clip.associationRelationship === 'temporally_associated' ? 'border-dashed' : ''} ${active ? 'opacity-100' : 'opacity-75'}`}
                            onClick={() => dispatchSelection('clip', clip.id)}
                            style={{
                              left: x,
                              width,
                              background: 'repeating-linear-gradient(135deg, #e2e8f0 0, #e2e8f0 3px, #f8fafc 3px, #f8fafc 7px)',
                            }}
                            title={`${clip.label} · connection lifetime ${formatDuration(duration)} · observed active ${formatDuration(clip.activity.activeMs / 1000)}`}
                            type="button"
                          >
                            {clip.activity.completeRanges.map((range) => {
                              const rangeStartFrame = ((range.startMs - composition.sessionStartMs) / 1000) * composition.fps
                              const rangeEndFrame = ((range.endMs - composition.sessionStartMs) / 1000) * composition.fps
                              const rangeX = ((rangeStartFrame - start) / Math.max(1, end - start)) * width
                              const rangeWidth = Math.max(1, ((rangeEndFrame - rangeStartFrame) / Math.max(1, end - start)) * width)
                              return <i className="absolute inset-y-0" key={range.startMs} style={{ backgroundColor: `${color}26`, left: rangeX, width: rangeWidth }} />
                            })}
                            <span className="absolute left-0 right-0 top-1/2 h-px bg-slate-500/70" />
                            {activityColumns.map((sample) => {
                              const sampleFrame = ((sample.startMs - composition.sessionStartMs) / 1000) * composition.fps
                              const sampleX = Math.max(0, Math.min(Math.ceil(width) - 1, Math.floor(((sampleFrame - start) / Math.max(1, end - start)) * width)))
                              const outHeight = activityHeight(sample.payloadBytesOut, sample.packetsOut, activityMetrics)
                              const inHeight = activityHeight(sample.payloadBytesIn, sample.packetsIn, activityMetrics)
                              return (
                                <span key={sample.x}>
                                  {outHeight > 0 ? <i className="absolute bottom-1/2 bg-amber-500" style={{ height: outHeight, left: sampleX, width: activityMetrics.columnWidth }} title={activitySampleTitle(sample)} /> : null}
                                  {inHeight > 0 ? <i className="absolute top-1/2 bg-cyan-500" style={{ height: inHeight, left: sampleX, width: activityMetrics.columnWidth }} title={activitySampleTitle(sample)} /> : null}
                                </span>
                              )
                            })}
                          </button>
                        </div>
                      </div>
                    )
                  }) : null}
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
        {hiddenLaneCount > 0
          ? `${hiddenLaneCount} additional groups are outside the render budget. Narrow the time window or focus a domain.`
          : domainFocused
          ? 'Retained domain detail is windowed to keep playback bounded. Use 10s / 30s below for a closer view; hatching means capture was incomplete.'
          : overviewOnly
            ? 'Whole-session overview. Click a domain to load its bounded connection detail.'
            : 'Click a domain to focus it. Pale bars are connection lifetimes; colored spikes show the loaded activity resolution.'}
      </div>
    </div>
  )
}

function TreemapScene({
  composition,
  currentFrame,
  selectedServiceId,
}: {
  composition: SceneWindow
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

function frameToMs(frame: number, composition: SceneWindow) {
  return composition.sessionStartMs + (frame / composition.fps) * 1000
}

function formatTraffic(bytes: number, countersAvailable: boolean) {
  return countersAvailable ? formatBytes(bytes) : 'Counters unavailable'
}

function activityHeight(
  payloadBytes: number,
  packets: number,
  metrics: ReturnType<typeof activityVisualMetrics>,
) {
  if (payloadBytes <= 0) return packets > 0 ? metrics.packetOnlyHeight : 0
  return Math.min(
    metrics.maxDirectionalHeight,
    Math.max(metrics.minimumPayloadHeight, metrics.minimumPayloadHeight + Math.log2(1 + payloadBytes / 64) * 2.5),
  )
}

function activitySampleTitle(sample: SceneActivityColumn) {
  return `${formatActivityTimestamp(sample.startMs)}–${formatActivityTimestamp(sample.endMs)}\nClient → remote: ${formatBytes(sample.payloadBytesOut)} payload / ${sample.packetsOut} packets\nRemote → client: ${formatBytes(sample.payloadBytesIn)} payload / ${sample.packetsIn} packets`
}

function formatActivityTimestamp(milliseconds: number) {
  return `${formatClock(milliseconds)}.${String(new Date(milliseconds).getMilliseconds()).padStart(3, '0')}`
}

function associationLabel(relationship: 'first_party' | 'cname_related' | 'temporally_associated') {
  switch (relationship) {
    case 'first_party':
      return 'first-party'
    case 'cname_related':
      return 'CNAME-linked'
    case 'temporally_associated':
      return 'associated'
  }
}

function colorForService(serviceId: string) {
  let hash = 0
  for (let index = 0; index < serviceId.length; index += 1) {
    hash = (hash * 31 + serviceId.charCodeAt(index)) >>> 0
  }
  return palette[hash % palette.length]
}

function dispatchSelection(kind: 'clip' | 'service' | 'toggle-service' | 'focus-service' | 'clear-focus', id: string) {
  if (typeof window === 'undefined') {
    return
  }
  window.dispatchEvent(new CustomEvent('infrareveal:select', { detail: { kind, id } }))
}
