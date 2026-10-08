import { useMemo } from 'react'
import { useCurrentFrame } from 'remotion'
import { buildTreemap } from '../model/treemap'
import type { SceneWindow } from '../timeline/selectors/selectSceneWindow'
import { formatBytes, formatClock } from '../views/formatters'

export type { SceneWindow } from '../timeline/selectors/selectSceneWindow'

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

export function SessionComposition({ sceneWindow }: { sceneWindow: SceneWindow }) {
  const frame = useCurrentFrame()
  return (
    <div className="h-full w-full bg-[#f8fafc] text-slate-950">
      <TreemapScene composition={sceneWindow} currentFrame={frame} selectedServiceId={null} />
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

function frameToMs(frame: number, composition: SceneWindow) {
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

function dispatchSelection(kind: 'service', id: string) {
  if (typeof window === 'undefined') {
    return
  }
  window.dispatchEvent(new CustomEvent('infrareveal:select', { detail: { kind, id } }))
}
