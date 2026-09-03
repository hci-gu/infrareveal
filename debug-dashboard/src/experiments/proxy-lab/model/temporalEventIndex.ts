import type { PipelineDirection, PipelineEvent, PipelineEventKind, PipelineStage } from '../types'
import { comparePipelineEvents } from './projectRecordedEvents'

export type EventFilters = {
  clients?: Iterable<string>
  traceIds?: Iterable<string>
  kinds?: Iterable<PipelineEventKind>
  stages?: Iterable<PipelineStage>
  directions?: Iterable<PipelineDirection>
}

type Facet = 'client' | 'traceId' | 'kind' | 'stage' | 'direction'

/** Incremental time-bucket index used by both recorded and live projections. */
export class TemporalEventIndex {
  private readonly events = new Map<string, PipelineEvent>()
  private readonly buckets = new Map<number, Set<string>>()
  private readonly facets: Record<Facet, Map<string, Set<string>>> = {
    client: new Map(), traceId: new Map(), kind: new Map(), stage: new Map(), direction: new Map(),
  }

  constructor(private readonly bucketMs = 1000) {
    if (!Number.isFinite(bucketMs) || bucketMs <= 0) throw new Error('bucketMs must be positive')
  }

  upsert(event: PipelineEvent) {
    this.remove(event.id)
    if (!Number.isFinite(event.occurredAtMs)) return
    this.events.set(event.id, event)
    add(this.buckets, this.bucket(event.occurredAtMs), event.id)
    add(this.facets.traceId, event.traceId, event.id)
    add(this.facets.kind, event.kind, event.id)
    add(this.facets.stage, event.stage, event.id)
    if (event.summary.clientIp) add(this.facets.client, event.summary.clientIp, event.id)
    if (event.direction) add(this.facets.direction, event.direction, event.id)
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
    remove(this.facets.traceId, event.traceId, id)
    remove(this.facets.kind, event.kind, id)
    remove(this.facets.stage, event.stage, id)
    if (event.summary.clientIp) remove(this.facets.client, event.summary.clientIp, id)
    if (event.direction) remove(this.facets.direction, event.direction, id)
    this.events.delete(id)
  }

  query(fromMs: number, toMs: number, filters: EventFilters = {}) {
    if (!Number.isFinite(fromMs) || !Number.isFinite(toMs) || toMs <= fromMs) return []
    const timeIds = new Set<string>()
    for (let bucket = this.bucket(fromMs); bucket <= this.bucket(toMs - 1); bucket += this.bucketMs) {
      for (const id of this.buckets.get(bucket) ?? []) timeIds.add(id)
    }

    const filterSets = [
      this.filterSet('client', filters.clients),
      this.filterSet('traceId', filters.traceIds),
      this.filterSet('kind', filters.kinds),
      this.filterSet('stage', filters.stages),
      this.filterSet('direction', filters.directions),
    ].filter((set): set is Set<string> => set !== null)

    return Array.from(timeIds)
      .filter((id) => filterSets.every((set) => set.has(id)))
      .flatMap((id) => {
        const event = this.events.get(id)
        return event && event.occurredAtMs >= fromMs && event.occurredAtMs < toMs ? [event] : []
      })
      .sort(comparePipelineEvents)
  }

  nearestBefore(cursorMs: number, traceId: string) {
    let nearest: PipelineEvent | null = null
    for (const id of this.facets.traceId.get(traceId) ?? []) {
      const event = this.events.get(id)
      if (!event || event.occurredAtMs > cursorMs) continue
      if (!nearest || comparePipelineEvents(nearest, event) < 0) nearest = event
    }
    return nearest
  }

  clear() {
    this.events.clear()
    this.buckets.clear()
    Object.values(this.facets).forEach((facet) => facet.clear())
  }

  get size() {
    return this.events.size
  }

  private bucket(timeMs: number) {
    return Math.floor(timeMs / this.bucketMs) * this.bucketMs
  }

  private filterSet(facet: Facet, values?: Iterable<string>) {
    if (!values) return null
    const ids = new Set<string>()
    for (const value of values) for (const id of this.facets[facet].get(value) ?? []) ids.add(id)
    return ids
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
