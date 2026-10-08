import { flowTrackAt, indexFlowTracks, isTrafficConnection, parseEpoch, routeForFlowAt, routeBindingKey } from '@infrareveal/session-state'
import type { Flow, FlowActivityChunk, FlowAssociation, FlowAttribution, FlowTrackIdentity, GatewayData, Route } from '@infrareveal/session-state'
import { decodeActivityChunk, type FlowActivitySample } from '../shared/activity/decodeActivityChunk'

export const FPS = 30
export const COMPOSITION_WIDTH = 1440
export const COMPOSITION_HEIGHT = 810

export type Confidence = FlowAttribution['confidence'] | 'pending'

export type FlowActivitySummary = {
  samples: FlowActivitySample[]
  completeRanges: Array<{ startMs: number; endMs: number }>
  activeMs: number
  coveredMs: number
  idleMs: number
  payloadBytesOut: number
  payloadBytesIn: number
  wireBytesOut: number
  wireBytesIn: number
  packetsOut: number
  packetsIn: number
  bucketMs: number | null
  droppedEvents: number
  captureComplete: boolean
  captureAvailable: boolean
}

export type ServiceGroup = {
  id: string
  label: string
  sourceSignal: string
  confidence: Confidence
  destinationIPs: string[]
  hostnames: string[]
  clientIPs: string[]
  providerLabel: string
  totalBytes: number
  packetCount: number
  flowCount: number
  firstSeenMs: number
  lastSeenMs: number
  lastActivityMs: number | null
  routeCompleteCount: number
  routeCount: number
  associatedFlowCount: number
}

export type TimelineClip = {
  id: string
  flowId: string
  serviceGroupId: string
  serviceGroupLabel: string
  label: string
  clientIP: string
  destinationIP: string
  destinationPort: number
  protocol: string
  state: string
  startMs: number
  endMs: number
  lastActivityMs: number | null
  startFrame: number
  durationFrames: number
  bytes: number
  packets: number
  confidence: Confidence
  explanation: string
  sourceSignal: string
  associationRelationship: FlowAssociation['relationship'] | null
  associationConfidence: FlowAssociation['confidence'] | null
  associationScore: number | null
  associationExplanation: string
  activity: FlowActivitySummary
}

export type TimelineLane = {
  id: string
  label: string
  serviceGroupId: string
  totalBytes: number
  clips: TimelineClip[]
}

export type SessionComposition = {
  fps: number
  width: number
  height: number
  sessionStartMs: number
  sessionEndMs: number
  durationInFrames: number
  clips: TimelineClip[]
  lanes: TimelineLane[]
  serviceGroups: ServiceGroup[]
  captureStatus: GatewayData['flowActivityStatuses'][number] | null
  totals: {
    flowCount: number
    attributedCount: number
    routeCount: number
    byteCount: number
    packetCount: number
    trafficCountersAvailable: boolean
  }
}

type CachedClip = { signature: string; clip: TimelineClip }

/** Derives the final flow identity and activity once, retaining unchanged clips. */
export class SessionCompositionProjector {
  private readonly clips = new Map<string, CachedClip>()

  project(data: GatewayData, bounds: { sessionStartMs: number; sessionEndMs: number }): Omit<SessionComposition, 'lanes' | 'serviceGroups'> {
    const { sessionStartMs, sessionEndMs } = bounds
    const flows = data.flows.filter(isTrafficConnection)
    const flowIDs = new Set(flows.map(flow => flow.id))
    const trackIndex = indexFlowTracks(data)
    const chunksByFlow = new Map<string, FlowActivityChunk[]>()
    for (const chunk of data.flowActivityChunks) {
      if (!flowIDs.has(chunk.flow)) continue
      const current = chunksByFlow.get(chunk.flow) ?? []
      current.push(chunk)
      chunksByFlow.set(chunk.flow, current)
    }
    const activityWindowSignature = recordsSignature(data.flowActivityWindows)
    const clips = flows.map(flow => {
      const identity = flowTrackAt(trackIndex, flow)
      const chunks = chunksByFlow.get(flow.id) ?? []
      const signature = [sessionStartMs, recordSignature(flow), JSON.stringify(identity), recordsSignature(chunks), activityWindowSignature].join('|')
      const cached = this.clips.get(flow.id)
      if (cached?.signature === signature) return cached.clip
      const clip = buildClip(flow, sessionStartMs, identity, chunks, data.flowActivityWindows)
      this.clips.set(flow.id, { signature, clip })
      return clip
    }).sort((a, b) => a.startFrame - b.startFrame || b.bytes - a.bytes)
    for (const id of this.clips.keys()) if (!flowIDs.has(id)) this.clips.delete(id)

    const routes = new Map<string, Route>()
    for (const flow of flows) {
      const route = routeForFlowAt(flow, data.routes, sessionEndMs)
      if (route) routes.set(routeBindingKey(flow), route)
    }
    return {
      fps: FPS,
      width: COMPOSITION_WIDTH,
      height: COMPOSITION_HEIGHT,
      sessionStartMs,
      sessionEndMs,
      durationInFrames: Math.max(1, Math.ceil((sessionEndMs - sessionStartMs) / 1000 * FPS)),
      clips,
      captureStatus: data.flowActivityStatuses[0] ?? null,
      totals: {
        flowCount: flows.length,
        attributedCount: new Set(data.attributions.filter(item => flowIDs.has(item.flow)).map(item => item.flow)).size,
        routeCount: new Set([...routes.values()].filter(route => route.hops?.some(h => h.address && h.address !== route.destination_ip)).map(routeBindingKey)).size,
        byteCount: flows.reduce((total, flow) => total + flow.bytes_in + flow.bytes_out, 0),
        packetCount: flows.reduce((total, flow) => total + flow.packets_in + flow.packets_out, 0),
        trafficCountersAvailable: flows.some(flow => flow.bytes_in > 0 || flow.bytes_out > 0 || flow.packets_in > 0 || flow.packets_out > 0),
      },
    }
  }
}

function recordsSignature(records: Array<{ id: string; created?: string; updated?: string }>) {
  return records.map(recordSignature).join(',')
}

function recordSignature(record?: { id: string; created?: string; updated?: string }) {
  if (!record) return ''
  const revision = record.updated || record.created
  return revision ? `${record.id}@${revision}` : JSON.stringify(record)
}

function buildClip(
  flow: Flow,
  sessionStartMs: number,
  identity: FlowTrackIdentity,
  activityChunks: FlowActivityChunk[],
  activityWindows: GatewayData['flowActivityWindows'],
): TimelineClip {
  const { attribution, association } = identity
  const startMs = parseEpoch(flow.start || flow.created || flow.updated, sessionStartMs)
  const endMs = Math.max(startMs, parseEpoch(flow.last_seen || flow.updated || flow.created, startMs))
  const activity = buildFlowActivitySummary(startMs, endMs, activityChunks, activityWindows)
  const lastActivityMs = activity.samples.reduce<number | null>((latest, sample) => {
    const active = sample.payloadBytesOut > 0 || sample.payloadBytesIn > 0 || sample.packetsOut > 0 || sample.packetsIn > 0
    return active ? latestTimestamp(latest, sample.startMs + sample.durationMs) : latest
  }, null)
  return {
    id: `clip:${flow.id}`,
    flowId: flow.id,
    serviceGroupId: identity.id,
    serviceGroupLabel: identity.label,
    label: identity.hostname,
    clientIP: flow.client_ip,
    destinationIP: flow.destination_ip,
    destinationPort: flow.destination_port,
    protocol: flow.protocol,
    state: flow.state,
    startMs,
    endMs,
    lastActivityMs,
    startFrame: Math.max(0, Math.round((startMs - sessionStartMs) / 1000 * FPS)),
    durationFrames: Math.max(1, Math.round((endMs - startMs) / 1000 * FPS)),
    bytes: Math.max(0, flow.bytes_in + flow.bytes_out),
    packets: Math.max(0, flow.packets_in + flow.packets_out),
    confidence: attribution?.confidence ?? 'pending',
    explanation: attribution?.explanation || 'No supported hostname attribution',
    sourceSignal: attribution?.source_signal || 'Observed socket',
    associationRelationship: association?.relationship ?? null,
    associationConfidence: association?.confidence ?? null,
    associationScore: association?.score ?? null,
    associationExplanation: association?.explanation || '',
    activity,
  }
}

function buildFlowActivitySummary(
  flowStartMs: number,
  flowEndMs: number,
  chunks: FlowActivityChunk[],
  windows: GatewayData['flowActivityWindows'],
): FlowActivitySummary {
  const byStart = new Map<number, FlowActivitySample>()
  let droppedEvents = 0
  let wireBytesOut = 0
  let wireBytesIn = 0
  const bucketSizes = new Set<number>()
  for (const chunk of chunks) {
    droppedEvents += Math.max(0, chunk.dropped_events || 0)
    wireBytesOut += Math.max(0, chunk.wire_bytes_out || 0)
    wireBytesIn += Math.max(0, chunk.wire_bytes_in || 0)
    if (positiveInteger(chunk.bucket_ms)) bucketSizes.add(chunk.bucket_ms)
    for (const sample of decodeActivityChunk(chunk)) {
      if (sample.startMs >= flowEndMs || sample.startMs + sample.durationMs <= flowStartMs) continue
      const previous = byStart.get(sample.startMs)
      if (!previous || sample.payloadBytesOut + sample.payloadBytesIn >= previous.payloadBytesOut + previous.payloadBytesIn) {
        byStart.set(sample.startMs, sample)
      }
    }
  }
  const samples = Array.from(byStart.values()).sort((left, right) => left.startMs - right.startMs)
  const activeMs = samples.reduce(
    (total, sample) => total + Math.max(0, Math.min(flowEndMs, sample.startMs + sample.durationMs) - Math.max(flowStartMs, sample.startMs)),
    0,
  )
  const relevantWindows = windows.filter((window) => {
    const start = Date.parse(window.window_start)
    return Number.isFinite(start) && start < flowEndMs && start + window.window_ms > flowStartMs
  })
  const windowDrops = relevantWindows.reduce((total, window) => total + Math.max(0, window.dropped_events || 0), 0)
  droppedEvents = Math.max(droppedEvents, windowDrops)
  const completeRanges = mergeIntervals(
    relevantWindows
      .filter((window) => window.capture_complete && window.dropped_events === 0)
      .map((window) => {
        const start = Date.parse(window.window_start)
        return [Math.max(flowStartMs, start), Math.min(flowEndMs, start + window.window_ms)] as const
      })
      .filter(([start, end]) => Number.isFinite(start) && end > start),
  ).map(([startMs, endMs]) => ({ startMs, endMs }))
  const coveredMs = completeRanges.reduce((total, range) => total + range.endMs - range.startMs, 0)
  return {
    samples,
    completeRanges,
    activeMs,
    coveredMs,
    idleMs: Math.max(0, coveredMs - activeMs),
    payloadBytesOut: samples.reduce((total, sample) => total + sample.payloadBytesOut, 0),
    payloadBytesIn: samples.reduce((total, sample) => total + sample.payloadBytesIn, 0),
    wireBytesOut,
    wireBytesIn,
    packetsOut: samples.reduce((total, sample) => total + sample.packetsOut, 0),
    packetsIn: samples.reduce((total, sample) => total + sample.packetsIn, 0),
    bucketMs: bucketSizes.size === 1 ? Array.from(bucketSizes)[0] : null,
    droppedEvents,
    captureComplete: coveredMs >= Math.max(0, flowEndMs - flowStartMs) && droppedEvents === 0,
    captureAvailable: relevantWindows.length > 0 || chunks.length > 0,
  }
}

function mergeIntervals(intervals: ReadonlyArray<readonly [number, number]>) {
  const ordered = intervals.slice().sort((left, right) => left[0] - right[0])
  const result: Array<[number, number]> = []
  let start = Number.NaN
  let end = Number.NaN
  for (const interval of ordered) {
    if (!Number.isFinite(start)) {
      ;[start, end] = interval
    } else if (interval[0] <= end) {
      end = Math.max(end, interval[1])
    } else {
      result.push([start, end])
      ;[start, end] = interval
    }
  }
  if (Number.isFinite(start)) result.push([start, end])
  return result
}

function positiveInteger(value: unknown) {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isInteger(number) && number > 0 ? number : null
}

function latestTimestamp(left: number | null, right: number | null) {
  if (left === null) return right
  if (right === null) return left
  return Math.max(left, right)
}
