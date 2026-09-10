import type { FlowActivityChunk } from '@infrareveal/session-state'
import { parseEpoch } from '@infrareveal/session-state'
import type { BundledMapArc } from './bundleMapArcs'
import type { MapFlowInterval, MapTimelineScene } from './mapModel'

export const TRAFFIC_BUCKET_MS = 500
export const TRAFFIC_HISTORY_LENGTH = 12
export const TRAFFIC_TRAVEL_SECONDS = 4

type Sample = { bytesPerSecond: number; packetsPerSecond: number }
type ActivityChunk = {
  startMs: number
  endMs: number
  bucketMs: number
  updatedMs: number
  complete: boolean
  samples: Map<number, Sample>
}
export type MapTrafficIndex = Map<string, ActivityChunk[]>
export type TrafficSource = 'sampled' | 'partial' | 'estimated' | 'unavailable'
export type TrafficProfile = {
  rates: number[]
  packets: number[]
  source: TrafficSource
}
export type TrafficArc = BundledMapArc & { radii: number[]; peakBytesPerSecond: number }

/** Decode once per detail revision; sparse complete buckets are measured silence. */
export function indexMapTraffic(chunks: readonly FlowActivityChunk[]): MapTrafficIndex {
  const index: MapTrafficIndex = new Map()
  for (const chunk of chunks) {
    const value = chunk.samples
    if (!value || typeof value !== 'object' || Array.isArray(value)) continue
    const payload = value as Record<string, unknown>
    if (payload.version !== 1 || !Array.isArray(payload.samples)) continue
    const bucketMs = payload.bucket_ms ?? chunk.bucket_ms
    const durationMs = payload.chunk_ms ?? chunk.chunk_ms
    const startMs = parseEpoch(chunk.chunk_start, Number.NaN)
    if (!validInteger(bucketMs) || !validInteger(durationMs) || bucketMs < 20 || bucketMs > 5000 || durationMs > 60_000 || bucketMs > durationMs || !Number.isFinite(startMs)) continue
    const samples = new Map<number, Sample>()
    let malformed = false
    for (const row of payload.samples) {
      if (!Array.isArray(row) || row.length < 5 || !row.slice(0, 5).every(validInteger)) { malformed = true; continue }
      const [offset, bytesOut, bytesIn, packetsOut, packetsIn] = row as number[]
      if (offset >= durationMs || offset % bucketMs !== 0 || samples.has(offset)) { malformed = true; continue }
      samples.set(offset, { bytesPerSecond: (bytesOut + bytesIn) * 1000 / bucketMs, packetsPerSecond: (packetsOut + packetsIn) * 1000 / bucketMs })
    }
    const siblings = index.get(chunk.flow) ?? []
    siblings.push({ startMs, endMs: startMs + durationMs, bucketMs, updatedMs: parseEpoch(chunk.updated_at_source, 0), complete: !malformed && chunk.capture_complete && chunk.dropped_events === 0, samples })
    index.set(chunk.flow, siblings)
  }
  // A single finest available observation wins at each instant, never both LODs.
  for (const chunks of index.values()) chunks.sort((a, b) => a.bucketMs - b.bucketMs || b.updatedMs - a.updatedMs)
  return index
}

export function projectTrafficProfiles(scene: MapTimelineScene, index: MapTrafficIndex, anchorMs: number): Map<string, TrafficProfile> {
  const profiles = new Map<string, TrafficProfile>()
  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > anchorMs) continue
    const rates = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    const packets = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    const sources = new Set<TrafficSource>()
    for (const flow of endpoint.flows) {
      if (flow.startMs > anchorMs || flow.endMs < anchorMs - TRAFFIC_HISTORY_LENGTH * TRAFFIC_BUCKET_MS) continue
      for (let i = 0; i < TRAFFIC_HISTORY_LENGTH; i += 1) {
        const end = anchorMs - i * TRAFFIC_BUCKET_MS
        const start = Math.max(end - TRAFFIC_BUCKET_MS, endpoint.availableFromMs, flow.startMs)
        const boundedEnd = Math.min(end, Math.max(flow.endMs, flow.startMs + 1))
        if (start >= boundedEnd) continue
        const observation = trafficInBin(flow, index.get(flow.id), start, boundedEnd)
        rates[i] += observation.bytesPerSecond
        packets[i] += observation.packetsPerSecond
        sources.add(observation.source)
      }
    }
    const source = sources.has('estimated') ? 'estimated' : sources.has('partial') || sources.has('unavailable') ? 'partial' : sources.has('sampled') ? 'sampled' : 'unavailable'
    profiles.set(endpoint.id, { rates, packets, source })
  }
  return profiles
}

export function volumeArcs(routes: BundledMapArc[], profiles: Map<string, TrafficProfile>): TrafficArc[] {
  return routes.map((arc) => {
    const rates = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    const packets = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    for (const endpointId of arc.endpointIds) {
      const profile = profiles.get(endpointId)
      if (!profile) continue
      for (let i = 0; i < TRAFFIC_HISTORY_LENGTH; i += 1) {
        rates[i] += profile.rates[i]
        packets[i] += profile.packets[i]
      }
    }
    return { ...arc, radii: rates.map((rate, i) => trafficRadius(rate, packets[i])), peakBytesPerSecond: Math.max(...rates) }
  }).filter((arc) => arc.radii.some((radius) => radius > 0))
}

/** One fixed scale across routes: ~1 px for small exchanges, ~10 px at 1 MB/s. */
export function trafficRadius(bytesPerSecond: number, packetsPerSecond = 0): number {
  if (!Number.isFinite(bytesPerSecond) || bytesPerSecond < 0 || !Number.isFinite(packetsPerSecond) || packetsPerSecond < 0) return 0
  if (bytesPerSecond === 0) return packetsPerSecond > 0 ? 0.65 : 0
  return Math.min(16, 0.45 + 2.8 * Math.pow(bytesPerSecond / 32_000, 0.36))
}

function trafficInBin(flow: MapFlowInterval, chunks: ActivityChunk[] | undefined, start: number, end: number): Sample & { source: TrafficSource } {
  if (!chunks?.length) {
    const seconds = Math.max(1, (flow.endMs - flow.startMs) / 1000)
    const fraction = (end - start) / TRAFFIC_BUCKET_MS
    return { bytesPerSecond: flow.bytes / seconds * fraction, packetsPerSecond: flow.packets / seconds * fraction, source: 'estimated' }
  }
  let cursor = start
  let bytesPerSecond = 0
  let packetsPerSecond = 0
  let partial = false
  while (cursor < end) {
    const chunk = chunks.find((chunk) => chunk.startMs <= cursor && chunk.endMs > cursor)
    let next = Math.min(end, ...chunks.filter((chunk) => chunk.startMs > cursor).map((chunk) => chunk.startMs))
    if (chunk) {
      const offset = Math.floor((cursor - chunk.startMs) / chunk.bucketMs) * chunk.bucketMs
      next = Math.min(next, chunk.endMs, chunk.startMs + offset + chunk.bucketMs)
      const sample = chunk.samples.get(offset)
      const fraction = (next - cursor) / TRAFFIC_BUCKET_MS
      bytesPerSecond += (sample?.bytesPerSecond ?? 0) * fraction
      packetsPerSecond += (sample?.packetsPerSecond ?? 0) * fraction
      partial ||= !chunk.complete
    } else partial = true
    cursor = next
  }
  return { bytesPerSecond, packetsPerSecond, source: partial ? 'partial' : 'sampled' }
}

function validInteger(value: unknown): value is number {
  return typeof value === 'number' && Number.isSafeInteger(value) && value >= 0
}
