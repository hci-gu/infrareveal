import type { PipelineEvent } from '../types'
import { comparePipelineEvents } from './projectRecordedEvents'

/** Incremental time-bucket index used by both recorded and live projections. */
export class TemporalEventIndex {
  private readonly events = new Map<string, PipelineEvent>()
  private readonly buckets = new Map<number, Set<string>>()

  constructor(private readonly bucketMs = 1000) {
    if (!Number.isFinite(bucketMs) || bucketMs <= 0) throw new Error('bucketMs must be positive')
  }

  upsert(event: PipelineEvent) {
    this.remove(event.id)
    if (!Number.isFinite(event.occurredAtMs)) return
    this.events.set(event.id, event)
    add(this.buckets, this.bucket(event.occurredAtMs), event.id)
  }

  synchronize(events: readonly PipelineEvent[]) {
    const nextIds = new Set(events.map((event) => event.id))
    for (const id of this.events.keys()) if (!nextIds.has(id)) this.remove(id)
    for (const event of events) this.upsert(event)
  }

  remove(id: string) {
    const event = this.events.get(id)
    if (!event) return
    remove(this.buckets, this.bucket(event.occurredAtMs), id)
    this.events.delete(id)
  }

  query(fromMs: number, toMs: number) {
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) return []
    const timeIds = new Set<string>()
    for (let bucket = this.bucket(fromMs); bucket <= this.bucket(toMs - 1); bucket += this.bucketMs) {
      for (const id of this.buckets.get(bucket) ?? []) timeIds.add(id)
    }

    return Array.from(timeIds)
      .flatMap((id) => {
        const event = this.events.get(id)
        return event && event.occurredAtMs >= fromMs && event.occurredAtMs < toMs ? [event] : []
      })
      .sort(comparePipelineEvents)
  }

  clear() {
    this.events.clear()
    this.buckets.clear()
  }

  get size() {
    return this.events.size
  }

  private bucket(timeMs: number) {
    return Math.floor(timeMs / this.bucketMs) * this.bucketMs
  }

}

function add<Key>(index: Map<Key, Set<string>>, key: Key, id: string) {
  const ids = index.get(key) ?? new Set<string>()
  ids.add(id)
  index.set(key, ids)
}

function remove<Key>(index: Map<Key, Set<string>>, key: Key, id: string) {
  const ids = index.get(key)
  ids?.delete(id)
  if (ids?.size === 0) index.delete(key)
}
