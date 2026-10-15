import { captureQuality, seriesKey } from '@infrareveal/session-state'
import type { CaptureInterval, TrafficChunk } from '@infrareveal/session-state'
import type { BundledMapArc } from './bundleMapArcs'
import type { MapTimelineScene } from './mapModel'
export const TRAFFIC_BUCKET_MS = 500
export const TRAFFIC_HISTORY_LENGTH = 12
export const TRAFFIC_TRAVEL_SECONDS = 4

/** Preserve sub-frame GPU precision after weeks of uptime. Both stream shaders
 * repeat on this period, so wrapping it cannot move the travelling accent. */
export function trafficShaderClock(seconds: number) {
  const period = TRAFFIC_TRAVEL_SECONDS * 256
  return ((seconds % period) + period) % period
}


type RateSample = { start: number; end: number; sent: number; received: number; packetsSent: number; packetsReceived: number }
export type MapTrafficIndex = Map<string, RateSample[]> & { coverage?: CaptureInterval[] }
export type TrafficSource = 'sampled' | 'partial' | 'unavailable'
export type TrafficProfile = {
  rates: number[]
  packets: number[]
  source: TrafficSource
  inRates?: number[]
  outRates?: number[]
  inPackets?: number[]
  outPackets?: number[]
}
export type TrafficArc = BundledMapArc & { radii: number[]; peakBytesPerSecond: number; direction?: number }


export function indexMapTraffic(chunks: readonly TrafficChunk[], coverage: CaptureInterval[] = []): MapTrafficIndex {
  const index: MapTrafficIndex = new Map()
  for (const chunk of chunks) {
    const key = seriesKey(chunk), samples = index.get(key) ?? []
    for (const sample of chunk.samples) samples.push({ start: chunk.start_ms + sample[0], end: chunk.start_ms + sample[0] + chunk.bucket_ms, sent: sample[3], received: sample[4], packetsSent: sample[5], packetsReceived: sample[6] })
    index.set(key, samples)
  }
  index.coverage = coverage
  return index
}
/** Workspace totals change more often than captured rate buckets or flow evidence. */
export function createTrafficProfileCache() {
  let previousKey = ''
  let previousIndex: MapTrafficIndex | undefined
  let profiles: Map<string, TrafficProfile> | undefined
  return (scene: MapTimelineScene, index: MapTrafficIndex, anchorMs: number) => {
    const key = JSON.stringify([anchorMs, scene.endpoints.map(endpoint => [endpoint.id, endpoint.availableFromMs, endpoint.series])])
    if (!profiles || index !== previousIndex || key !== previousKey) {
      profiles = projectTrafficProfiles(scene, index, anchorMs)
      previousIndex = index
      previousKey = key
    }
    return profiles
  }
}

export function projectTrafficProfiles(scene: MapTimelineScene, index: MapTrafficIndex, anchorMs: number): Map<string, TrafficProfile> {
  const profiles = new Map<string, TrafficProfile>()
  for (const endpoint of scene.endpoints) {
    if (endpoint.availableFromMs > anchorMs) continue
    const rates = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    const packets = new Array<number>(TRAFFIC_HISTORY_LENGTH).fill(0)
    const inRates = rates.slice(), outRates = rates.slice(), inPackets = rates.slice(), outPackets = rates.slice()
    const sources = new Set<TrafficSource>()
    for (const flow of endpoint.series) {
      if (flow.startMs > anchorMs || flow.endMs < anchorMs - TRAFFIC_HISTORY_LENGTH * TRAFFIC_BUCKET_MS) continue
      for (let i = 0; i < TRAFFIC_HISTORY_LENGTH; i += 1) {
        const end = anchorMs - i * TRAFFIC_BUCKET_MS
        const start = Math.max(end - TRAFFIC_BUCKET_MS, endpoint.availableFromMs, flow.startMs)
        const boundedEnd = Math.min(end, Math.max(flow.endMs, flow.startMs + 1))
        if (start >= boundedEnd) continue
        const observation = trafficInBin(index.get(flow.id), index.coverage ?? [], start, boundedEnd)
        rates[i] += observation.bytesPerSecond
        packets[i] += observation.packetsPerSecond
        inRates[i] += observation.inRate; outRates[i] += observation.outRate
        inPackets[i] += observation.inPackets; outPackets[i] += observation.outPackets
        sources.add(observation.source)
      }
    }
    const source = sources.has('partial') || sources.has('unavailable') ? 'partial' : sources.has('sampled') ? 'sampled' : 'unavailable'
    profiles.set(endpoint.id, { rates, packets, source, inRates, outRates, inPackets, outPackets })
  }
  return profiles
}

export function volumeArcs<T extends { endpointIds: string[] }>(routes: T[], profiles: Map<string, TrafficProfile>): (T & { radii: number[]; peakBytesPerSecond: number })[] {
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


function trafficInBin(samples: RateSample[] | undefined, coverage: CaptureInterval[], start: number, end: number) {
  let sent = 0, received = 0, packetsSent = 0, packetsReceived = 0
  for (const sample of samples ?? []) {
    if (sample.start < start || sample.end > end) continue
    sent += sample.sent; received += sample.received; packetsSent += sample.packetsSent; packetsReceived += sample.packetsReceived
  }
  const factor = 1000 / TRAFFIC_BUCKET_MS
  const quality = captureQuality(coverage, start, end)
  return { bytesPerSecond: (sent+received)*factor, packetsPerSecond: (packetsSent+packetsReceived)*factor, inRate: received*factor, outRate: sent*factor, inPackets: packetsReceived*factor, outPackets: packetsSent*factor, source: quality === 'complete' ? 'sampled' as const : quality === 'unavailable' ? 'unavailable' as const : 'partial' as const }
}
/** Two independent volume lanes; incoming follows the same approximate geometry. */
export function directionalVolumeArcs<T extends { endpointIds: string[] }>(routes: T[], profiles: Map<string, TrafficProfile>) {
  return [1, -1].flatMap(direction => {
    const directional = new Map([...profiles].map(([key, value]) => [key, {...value, rates: direction === 1 ? (value.outRates ?? value.rates) : (value.inRates ?? value.rates.map(() => 0)), packets: direction === 1 ? (value.outPackets ?? value.packets) : (value.inPackets ?? value.packets.map(() => 0))}]))
    return volumeArcs(routes, directional).map(arc => ({...arc, direction}))
  })
}
