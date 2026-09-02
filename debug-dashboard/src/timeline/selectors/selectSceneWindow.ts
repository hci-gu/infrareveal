import type {
  FlowActivitySummary,
  ServiceGroup,
  SessionComposition,
  TimelineClip,
  TimelineLane,
} from '../../model/sessionModel'

const MAX_ACTIVITY_COLUMNS = 1024

export type SceneActivityColumn = {
  x: number
  startMs: number
  endMs: number
  payloadBytesOut: number
  payloadBytesIn: number
  packetsOut: number
  packetsIn: number
  complete: boolean
}

export type SceneClip = Omit<TimelineClip, 'activity'> & {
  activity: Omit<FlowActivitySummary, 'samples'>
  activityColumns: SceneActivityColumn[]
}

export type SceneLane = Omit<TimelineLane, 'clips'> & {
  clips: SceneClip[]
  flowCount: number
  associatedFlowCount: number
}

/** The bounded, JSON-serializable contract passed across the Remotion boundary. */
export type SceneWindow = Omit<SessionComposition, 'clips' | 'lanes' | 'serviceGroups'> & {
  fromMs: number
  toMs: number
  loadedRanges: Array<{ fromMs: number; toMs: number; complete: boolean }>
  clips: SceneClip[]
  lanes: SceneLane[]
  serviceGroups: ServiceGroup[]
}

export function selectSceneWindow(
  composition: SessionComposition,
  {
    fromMs,
    toMs,
    overview,
    focusedServiceId,
    selectedClipId,
    loadedRanges = [],
  }: {
    fromMs: number
    toMs: number
    overview: boolean
    focusedServiceId: string | null
    selectedClipId: string | null
    loadedRanges?: Array<{ fromMs: number; toMs: number; complete: boolean }>
  },
): SceneWindow {
  const boundedFromMs = Math.max(composition.sessionStartMs, Math.min(fromMs, composition.sessionEndMs))
  const boundedToMs = Math.max(boundedFromMs + 1, Math.min(toMs, composition.sessionEndMs))
  const overviewOnly = overview && !focusedServiceId
  const selectedClips = overviewOnly
    ? buildOverviewClips(composition)
    : composition.clips.filter((clip) => {
        const selected = clip.id === selectedClipId
        const focused = !focusedServiceId || clip.serviceGroupId === focusedServiceId
        return focused && (selected || (clip.startMs < boundedToMs && clip.endMs >= boundedFromMs))
      })
  const clips = selectedClips.map((clip) => materializeSceneClip(clip, boundedFromMs, boundedToMs))
  const clipsByID = new Map(clips.map((clip) => [clip.id, clip]))
  const clipsByService = new Map(clips.map((clip) => [clip.serviceGroupId, clip]))
  const serviceIDs = new Set(clips.map((clip) => clip.serviceGroupId))
  const serviceGroups = composition.serviceGroups.filter((group) => serviceIDs.has(group.id))
  const groupsByID = new Map(serviceGroups.map((group) => [group.id, group]))
  const lanes = overviewOnly
    ? composition.lanes.flatMap((lane) => {
        const group = groupsByID.get(lane.serviceGroupId)
        const clip = clipsByService.get(lane.serviceGroupId)
        return group && clip
          ? [{ ...lane, clips: [clip], flowCount: group.flowCount, associatedFlowCount: group.associatedFlowCount }]
          : []
      })
    : composition.lanes
        .filter((lane) => serviceIDs.has(lane.serviceGroupId))
        .map((lane) => {
          const laneClips = lane.clips.flatMap((clip) => {
            const sceneClip = clipsByID.get(clip.id)
            return sceneClip ? [sceneClip] : []
          })
          return {
            ...lane,
            clips: laneClips,
            flowCount: laneClips.length,
            associatedFlowCount: laneClips.filter((clip) => clip.associationRelationship === 'temporally_associated').length,
          }
        })

  return {
    ...composition,
    fromMs: boundedFromMs,
    toMs: boundedToMs,
    loadedRanges: mergeLoadedRanges(loadedRanges, boundedFromMs, boundedToMs),
    clips,
    lanes,
    serviceGroups,
    totals: overviewOnly
      ? composition.totals
      : {
          ...composition.totals,
          flowCount: clips.length,
          attributedCount: clips.filter((clip) => clip.confidence !== 'pending').length,
          byteCount: clips.reduce((total, clip) => total + clip.bytes, 0),
          packetCount: clips.reduce((total, clip) => total + clip.packets, 0),
        },
  }
}

function buildOverviewClips(composition: SessionComposition): TimelineClip[] {
  const clipsByService = new Map<string, TimelineClip>()
  for (const clip of composition.clips) {
    if (!clipsByService.has(clip.serviceGroupId)) clipsByService.set(clip.serviceGroupId, clip)
  }
  return composition.serviceGroups.flatMap((group) => {
    const representative = clipsByService.get(group.id)
    if (!representative) return []
    const startFrame = Math.max(0, Math.round(((group.firstSeenMs - composition.sessionStartMs) / 1000) * composition.fps))
    const durationFrames = Math.max(1, Math.round(((group.lastSeenMs - group.firstSeenMs) / 1000) * composition.fps))
    return [{
      ...representative,
      id: `overview:${group.id}`,
      label: group.label,
      serviceGroupLabel: group.label,
      startMs: group.firstSeenMs,
      endMs: group.lastSeenMs,
      lastActivityMs: group.lastActivityMs,
      startFrame,
      durationFrames,
      bytes: group.totalBytes,
      packets: group.packetCount,
      confidence: group.confidence,
      activity: {
        samples: [],
        completeRanges: [],
        activeMs: 0,
        coveredMs: 0,
        idleMs: 0,
        payloadBytesOut: 0,
        payloadBytesIn: 0,
        wireBytesOut: 0,
        wireBytesIn: 0,
        packetsOut: 0,
        packetsIn: 0,
        bucketMs: null,
        droppedEvents: 0,
        captureComplete: false,
        captureAvailable: false,
      },
    }]
  })
}

function materializeSceneClip(clip: TimelineClip, fromMs: number, toMs: number): SceneClip {
  const { samples, ...activity } = clip.activity
  const spanMs = Math.max(1, toMs - fromMs)
  const columnMs = Math.max(1, Math.ceil(spanMs / MAX_ACTIVITY_COLUMNS))
  const columns = new Map<number, SceneActivityColumn>()

  for (const sample of samples) {
    if (sample.startMs >= toMs || sample.startMs + sample.durationMs <= fromMs) continue
    const x = Math.max(0, Math.min(MAX_ACTIVITY_COLUMNS - 1, Math.floor((sample.startMs - fromMs) / columnMs)))
    const current = columns.get(x)
    if (current) {
      current.startMs = Math.min(current.startMs, sample.startMs)
      current.endMs = Math.max(current.endMs, sample.startMs + sample.durationMs)
      current.payloadBytesOut += sample.payloadBytesOut
      current.payloadBytesIn += sample.payloadBytesIn
      current.packetsOut += sample.packetsOut
      current.packetsIn += sample.packetsIn
      current.complete = current.complete && sample.complete
    } else {
      columns.set(x, {
        x,
        startMs: sample.startMs,
        endMs: sample.startMs + sample.durationMs,
        payloadBytesOut: sample.payloadBytesOut,
        payloadBytesIn: sample.payloadBytesIn,
        packetsOut: sample.packetsOut,
        packetsIn: sample.packetsIn,
        complete: sample.complete,
      })
    }
  }

  return { ...clip, activity, activityColumns: Array.from(columns.values()) }
}

function mergeLoadedRanges(
  ranges: Array<{ fromMs: number; toMs: number; complete: boolean }>,
  fromMs: number,
  toMs: number,
) {
  const clipped = ranges
    .map((range) => ({
      fromMs: Math.max(fromMs, range.fromMs),
      toMs: Math.min(toMs, range.toMs),
      complete: range.complete,
    }))
    .filter((range) => range.toMs > range.fromMs)
    .sort((left, right) => left.fromMs - right.fromMs)
  const merged: typeof clipped = []
  for (const range of clipped) {
    const previous = merged[merged.length - 1]
    if (previous && previous.complete === range.complete && range.fromMs <= previous.toMs) {
      previous.toMs = Math.max(previous.toMs, range.toMs)
    } else {
      merged.push({ ...range })
    }
  }
  return merged
}
