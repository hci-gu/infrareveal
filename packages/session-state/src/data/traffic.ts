import type { CaptureInterval, TrafficChunk } from './types'
export function seriesKey(chunk: TrafficChunk) { return JSON.stringify([chunk.capture_epoch, chunk.client_id, chunk.service_key, chunk.destination_id, chunk.destination_ip, chunk.protocol, chunk.destination_port, chunk.network_epoch]) }
export function serviceKey(chunk: Pick<TrafficChunk, 'client_id' | 'service_key'>) { return JSON.stringify([chunk.client_id, chunk.service_key]) }
export function captureQuality(coverage: readonly CaptureInterval[], from: number, to: number): 'complete' | 'partial' | 'unavailable' {
  if (to <= from) return 'complete'
  const intervals = coverage.filter(value => value.start_ms < to && value.end_ms > from).sort((a, b) => a.start_ms - b.start_ms)
  if (!intervals.length) return 'unavailable'
  let edge = from, complete = true
  for (const interval of intervals) {
    if (interval.start_ms > edge) complete = false
    if (interval.quality !== 'complete' || interval.dropped > 0) complete = false
    edge = Math.max(edge, interval.end_ms)
  }
  return complete && edge >= to ? 'complete' : 'partial'
}
/** Include completed bins only. A cursor never receives future bytes or interpolated volume. */
export function trafficTotals(chunks: readonly TrafficChunk[], from: number, to: number) {
  let sent = 0, received = 0, payloadSent = 0, payloadReceived = 0, packetsSent = 0, packetsReceived = 0
  for (const chunk of chunks) for (const sample of chunk.samples) {
    const start = chunk.start_ms + sample[0]
    if (start < from || start + chunk.bucket_ms > to) continue
    sent += sample[1]; received += sample[2]; payloadSent += sample[3]; payloadReceived += sample[4]; packetsSent += sample[5]; packetsReceived += sample[6]
  }
  return { sent, received, payloadSent, payloadReceived, packetsSent, packetsReceived }
}
