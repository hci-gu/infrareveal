import { getMapWindow } from './data/client'
import type { CaptureInterval, MapWindow, SessionManifest, TrafficChunk } from './data/types'

export const SEGMENT_MS = 30_000
const CACHE_BYTES = 384 * 1024 * 1024
export function windowBytes(value: MapWindow) {
  return 256 + value.series.reduce((n, chunk) => n + 700 + chunk.samples.length * 64, 0)
    + value.coverage.length * 256 + value.destinations.length * 512 + value.blocks.length * 512 + value.routes.length * 2048
}

type FetchWindow = typeof getMapWindow
/** Finalized traffic is immutable. Only the correction tail is replaced, using
 * one pinned database snapshot. Context that can change independently (blocks,
 * routes) is intentionally fetched by its own API instead of cached here. */
export class TrafficSegments {
  private entries = new Map<string, { window: MapWindow; bytes: number }>()
  private bytes = 0
  private scope = ''
  readonly stats = { requests: 0, hits: 0, bytes: 0, segments: 0 }
  constructor(private fetchWindow: FetchWindow = getMapWindow) {}
  clear() { this.entries.clear(); this.bytes = 0; this.stats.bytes = 0; this.stats.segments = 0 }
  async load(manifest: SessionManifest, from: number, to: number, resolution: number, signal: AbortSignal): Promise<MapWindow> {
    const policy = manifest.policy
    // JSON object key order is not part of the policy. PocketBase can emit the
    // same alias map in a different order on each manifest refresh.
    const scope = JSON.stringify([manifest.id, manifest.capture.epoch, policy.version, policy.bucket_ms, policy.chunk_ms, policy.correction_ms, policy.quiet_gap_ms, Object.entries(policy.aliases ?? {}).sort(([a], [b]) => a.localeCompare(b))])
    if (scope !== this.scope) { this.clear(); this.scope = scope }
    for (const [key, item] of this.entries) if (item.window.to_ms <= manifest.retained_from_ms) { this.entries.delete(key); this.bytes -= item.bytes }
    const floor = Math.max(from, manifest.retained_from_ms)
    const chunkMS = manifest.policy.chunk_ms || 5000
    const correctionMS = manifest.policy.correction_ms ?? 10000
    const finalized = manifest.active
      ? Math.floor((manifest.capture.confirmed_ms - correctionMS - chunkMS) / SEGMENT_MS) * SEGMENT_MS
      : to
    const stableEnd = Math.max(floor, Math.min(to, finalized))
    const ranges: [number, number, boolean][] = []
    for (let start = floor; start < stableEnd;) {
      const end = Math.min(stableEnd, (Math.floor(start / SEGMENT_MS) + 1) * SEGMENT_MS)
      ranges.push([start, end, true]); start = end
    }
    if (stableEnd < to) ranges.push([stableEnd, to, false])
    const parts: MapWindow[] = new Array(ranges.length)
    let next = 0
    const worker = async () => {
      while (next < ranges.length) {
        signal.throwIfAborted()
        const i = next++, [start, end, stable] = ranges[i]
        const key = JSON.stringify([scope, start, end, resolution])
        const cached = stable && this.entries.get(key)
        if (cached) {
          parts[i] = cached.window; this.stats.hits++
          this.entries.delete(key); this.entries.set(key, cached)
          continue
        }
        this.stats.requests++
        const window = await this.fetchWindow(manifest.id, start, end, resolution, signal, '', true)
        signal.throwIfAborted()
        parts[i] = window
        // A partial current response cannot be mistaken for a finalized segment.
        if (stable && window.to_ms === end && scope === this.scope) {
          const bytes = windowBytes(window)
          const old = this.entries.get(key); if (old) this.bytes -= old.bytes
          this.entries.set(key, { window, bytes }); this.bytes += bytes
          while (this.bytes > CACHE_BYTES && this.entries.size) {
            const [oldKey, item] = this.entries.entries().next().value!
            this.entries.delete(oldKey); this.bytes -= item.bytes
          }
        }
      }
    }
    // One shared display should never consume the server's entire snapshot pool.
    await Promise.all([worker(), worker()])
    signal.throwIfAborted()
    this.stats.bytes = this.bytes; this.stats.segments = this.entries.size
    const coverage = new Map<string, CaptureInterval>()
    const destinations = new Map<string, MapWindow['destinations'][number]>()
    const series: TrafficChunk[] = []
    let revision = manifest.revision, actualTo = floor
    for (const part of parts) {
      revision = Math.max(revision, part.revision); actualTo = Math.max(actualTo, part.to_ms)
      series.push(...part.series)
      for (const item of part.destinations) destinations.set(item.id, item)
      for (const interval of part.coverage) {
        const previous = coverage.get(interval.id)
        coverage.set(interval.id, previous ? { ...interval, start_ms: Math.min(previous.start_ms, interval.start_ms), end_ms: Math.max(previous.end_ms, interval.end_ms) } : interval)
      }
    }
    return { session_id: manifest.id, revision, from_ms: floor, to_ms: actualTo, resolution_ms: resolution, complete: true, series, segments: parts,
      coverage: [...coverage.values()].sort((a, b) => a.start_ms - b.start_ms), destinations: [...destinations.values()], blocks: [], routes: [] }
  }
}
