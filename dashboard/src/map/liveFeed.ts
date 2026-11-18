import { seriesKey } from '@infrareveal/session-state'
import type { TrafficChunk } from '@infrareveal/session-state'

export const FEED_TICK_MS = 250
export const FEED_SPAN_MS = 15_000
export const FEED_LIMIT = 200
/** A playhead jump larger than this restarts the feed instead of appending. */
export const FEED_JUMP_MS = 20_000

export type FeedLine = {
  id: string; atMs: number; clientIp: string; service: string; host: string
  endpoint: string; protocol: string; sent: number; received: number
}

/** Captured 50 ms samples merged per series into 250 ms ticks: readable, but
 * still a direct reading of capture, newest first. Only samples in [from, to). */
export function feedLines(chunks: readonly TrafficChunk[], fromMs: number, toMs: number, hidden?: (chunk: TrafficChunk) => boolean): FeedLine[] {
  const lines = new Map<string, FeedLine>()
  for (const chunk of chunks) {
    if (hidden?.(chunk)) continue
    const key = seriesKey(chunk)
    for (const sample of chunk.samples) {
      const at = chunk.start_ms + sample[0]
      if (at < fromMs || at >= toMs) continue
      const sent = sample[1], received = sample[2]
      if (sent <= 0 && received <= 0) continue
      const tick = Math.floor(at / FEED_TICK_MS) * FEED_TICK_MS
      const id = `${key}@${tick}`
      const line = lines.get(id) ?? {
        id, atMs: tick, clientIp: chunk.client_ip || chunk.client_id, service: chunk.service_label || chunk.destination_ip,
        host: chunk.evidence?.hostname || '', endpoint: `${chunk.destination_ip}:${chunk.destination_port}`, protocol: chunk.protocol, sent: 0, received: 0,
      }
      line.sent += sent
      line.received += received
      lines.set(id, line)
    }
  }
  return sortFeed([...lines.values()])
}

export const sortFeed = (lines: FeedLine[]) => lines.sort((a, b) => b.atMs - a.atMs || a.id.localeCompare(b.id))

/** Late-arriving capture fills in older ticks; the newest values for a tick win. */
export function mergeFeed(previous: readonly FeedLine[], next: readonly FeedLine[], limit = FEED_LIMIT): FeedLine[] {
  const byId = new Map(previous.map(line => [line.id, line]))
  for (const line of next) byId.set(line.id, line)
  return sortFeed([...byId.values()]).slice(0, limit)
}

/** Lines per second for the last `seconds` before the cursor, oldest first. */
export function feedRate(lines: readonly FeedLine[], cursorMs: number, seconds = 15): number[] {
  const bins = new Array<number>(seconds).fill(0)
  const end = Math.floor(cursorMs / 1000) * 1000
  for (const line of lines) {
    const index = seconds - 1 - Math.floor((end - Math.floor(line.atMs / 1000) * 1000) / 1000)
    if (index >= 0 && index < seconds) bins[index] += 1
  }
  return bins
}
