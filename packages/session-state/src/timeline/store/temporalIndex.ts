import { alignWindowStart, WINDOW_SEGMENT_MS } from '../domain/time'

type Interval = { startMs: number; endMs: number }

/** Duration-bounded temporal lookup for normalized PocketBase entities. */
export class TemporalBucketIndex {
  private readonly buckets = new Map<number, Set<string>>()
  private readonly intervals = new Map<string, Interval>()

  constructor(private readonly bucketMs = WINDOW_SEGMENT_MS) {}

  upsert(id: string, startMs: number, endMs = startMs) {
    this.remove(id)
    if (!Number.isFinite(startMs) || !Number.isFinite(endMs)) return
    const normalizedEnd = Math.max(startMs, endMs)
    this.intervals.set(id, { startMs, endMs: normalizedEnd })
    const first = alignWindowStart(startMs, this.bucketMs)
    const last = alignWindowStart(normalizedEnd, this.bucketMs)
    for (let bucket = first; bucket <= last; bucket += this.bucketMs) {
      const ids = this.buckets.get(bucket) ?? new Set<string>()
      ids.add(id)
      this.buckets.set(bucket, ids)
    }
  }

  remove(id: string) {
    const interval = this.intervals.get(id)
    if (!interval) return
    const first = alignWindowStart(interval.startMs, this.bucketMs)
    const last = alignWindowStart(interval.endMs, this.bucketMs)
    for (let bucket = first; bucket <= last; bucket += this.bucketMs) {
      const ids = this.buckets.get(bucket)
      ids?.delete(id)
      if (ids?.size === 0) this.buckets.delete(bucket)
    }
    this.intervals.delete(id)
  }

  query(fromMs: number, toMs: number) {
    const result = new Set<string>()
    const first = alignWindowStart(fromMs, this.bucketMs)
    const last = alignWindowStart(Math.max(fromMs, toMs - 1), this.bucketMs)
    for (let bucket = first; bucket <= last; bucket += this.bucketMs) {
      for (const id of this.buckets.get(bucket) ?? []) {
        const interval = this.intervals.get(id)
        if (interval && interval.startMs < toMs && interval.endMs >= fromMs) result.add(id)
      }
    }
    return result
  }

  clear() {
    this.buckets.clear()
    this.intervals.clear()
  }

  get size() {
    return this.intervals.size
  }
}
