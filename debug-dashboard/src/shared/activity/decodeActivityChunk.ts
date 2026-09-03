import type { FlowActivityChunk } from '@infrareveal/session-state'

export type FlowActivitySample = {
  startMs: number
  durationMs: number
  payloadBytesOut: number
  payloadBytesIn: number
  packetsOut: number
  packetsIn: number
  complete: boolean
}

/** Strictly decodes the persisted sparse v1 activity format. */
export function decodeActivityChunk(chunk: FlowActivityChunk): FlowActivitySample[] {
  const value = chunk.samples
  if (!value || typeof value !== 'object' || Array.isArray(value)) return []
  const payload = value as Record<string, unknown>
  if (payload.version !== 1 || !Array.isArray(payload.samples)) return []
  const bucketMs = payload.bucket_ms === undefined
    ? positiveInteger(chunk.bucket_ms)
    : positiveInteger(payload.bucket_ms)
  const chunkMs = payload.chunk_ms === undefined
    ? positiveInteger(chunk.chunk_ms)
    : positiveInteger(payload.chunk_ms)
  const chunkStartMs = Date.parse(chunk.chunk_start)
  if (!bucketMs || !chunkMs || bucketMs < 20 || bucketMs > 1000 || chunkMs > 60_000 || bucketMs > chunkMs || !Number.isFinite(chunkStartMs)) return []
  const samples: FlowActivitySample[] = []
  for (const row of payload.samples) {
    if (!Array.isArray(row) || row.length < 5) continue
    const numbers = row.slice(0, 5).map(nonNegativeInteger)
    if (numbers.some((item) => item === null)) continue
    const [offsetMs, payloadBytesOut, payloadBytesIn, packetsOut, packetsIn] = numbers as number[]
    if (offsetMs >= chunkMs || offsetMs % bucketMs !== 0) continue
    samples.push({
      startMs: chunkStartMs + offsetMs,
      durationMs: bucketMs,
      payloadBytesOut,
      payloadBytesIn,
      packetsOut,
      packetsIn,
      complete: chunk.capture_complete && chunk.dropped_events === 0,
    })
  }
  return samples
}

function positiveInteger(value: unknown) {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isInteger(number) && number > 0 ? number : null
}

function nonNegativeInteger(value: unknown) {
  const number = typeof value === 'number' ? value : Number.NaN
  return Number.isSafeInteger(number) && number >= 0 ? number : null
}
