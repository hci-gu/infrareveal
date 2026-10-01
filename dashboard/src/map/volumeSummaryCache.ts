import { parseEpoch } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import type { DestinationVolumeIndex, VolumeChunk } from './destinationVolumes'

const defaultUrl = typeof window === 'undefined' ? 'http://127.0.0.1:8090' : `${window.location.protocol}//${window.location.hostname}:8090`
const baseUrl = (import.meta.env.VITE_POCKETBASE_URL ?? defaultUrl).replace(/\/$/, '')
const fields = 'id,session,flow,chunk_start,chunk_ms,wire_bytes_in,wire_bytes_out,capture_complete,dropped_events,updated_at_source,updated'

/** Retain compact summaries; only changed flows need new sorted prefix sums. */
export class VolumeSummaryCache {
  index: DestinationVolumeIndex = new Map()
  private records = new Map<string, VolumeChunk>()
  private flows = new Map<string, Map<string, VolumeChunk>>()
  private dirty = new Set<string>()
  private deleted = new Map<string, number>()
  private revision = 0
  private watermark = 0
  private snapshotAt = -Infinity
  constructor(private sessionId: string) {}

  async refresh(signal: AbortSignal, fromMs: number, now = Date.now()) {
    const snapshot = !this.watermark || now - this.snapshotAt >= 60_000
    const revision = this.revision
    const incoming = await readVolumeChunks(this.sessionId, snapshot ? 0 : this.watermark, signal, fromMs)
    signal.throwIfAborted()
    if (snapshot) {
      const retained = new Set(incoming.map(record => record.id))
      for (const id of this.records.keys()) if (!retained.has(id)) this.remove(id)
      this.snapshotAt = now
      for (const [id, deletedAt] of this.deleted) if (deletedAt <= revision) this.deleted.delete(id)
    }
    for (const record of incoming) {
      this.watermark = Math.max(this.watermark, parseEpoch(record.updated, 0))
      if (this.deleted.has(record.id)) continue
      const previous = this.records.get(record.id)
      if (previous && fields.split(',').every(key => previous[key as keyof VolumeChunk] === record[key as keyof VolumeChunk])) continue
      if (previous) this.remove(previous.id)
      this.records.set(record.id, record)
      const flow = this.flows.get(record.flow) ?? new Map<string, VolumeChunk>()
      flow.set(record.id, record)
      this.flows.set(record.flow, flow)
      this.dirty.add(record.flow)
    }
    for (const record of this.records.values()) {
      if (parseEpoch(record.chunk_start, 0) + record.chunk_ms <= fromMs) this.remove(record.id)
    }
    return this.publish()
  }

  delete(id: string) {
    this.deleted.set(id, ++this.revision)
    this.remove(id)
    return this.publish()
  }

  private remove(id: string) {
    const record = this.records.get(id)
    if (!record) return
    this.records.delete(id)
    const flow = this.flows.get(record.flow)!
    flow.delete(id)
    if (!flow.size) this.flows.delete(record.flow)
    this.dirty.add(record.flow)
  }

  private publish() {
    if (!this.dirty.size) return this.index
    const index = new Map(this.index)
    for (const flow of this.dirty) {
      const records = this.flows.get(flow)
      const series = records && indexDestinationVolumes([...records.values()]).get(flow)
      if (series) index.set(flow, series)
      else index.delete(flow)
    }
    this.dirty.clear()
    return this.index = index
  }
}

export async function readVolumeChunks(sessionId: string, watermark: number, signal: AbortSignal, fromMs = 0): Promise<VolumeChunk[]> {
  const records: VolumeChunk[] = []
  let after = ''
  const sessionFilter = `session=${JSON.stringify(sessionId)}`
    + (fromMs ? ` && chunk_start >= ${JSON.stringify(new Date(fromMs - 60_000).toISOString().replace('T', ' '))}` : '')
  // Use storage revision, so a late write of an old capture chunk is still picked up.
  const updatedFilter = watermark ? ` && updated >= ${JSON.stringify(new Date(watermark - 30_000).toISOString().replace('T', ' '))}` : ''
  while (!signal.aborted) {
    const params = new URLSearchParams({ perPage: '500', sort: 'id', fields,
      filter: `${sessionFilter}${updatedFilter}${after ? ` && id > ${JSON.stringify(after)}` : ''}` })
    const response = await fetch(`${baseUrl}/api/collections/flow_activity_chunks/records?${params}`, { signal: AbortSignal.any([signal, AbortSignal.timeout(20_000)]) })
    if (!response.ok) throw new Error(`Destination totals request failed: ${response.status}`)
    const payload = await response.json() as { items: VolumeChunk[] }
    if (!Array.isArray(payload.items)) throw new Error('Missing destination totals')
    records.push(...payload.items.filter(record => record.session === sessionId && (!fromMs || parseEpoch(record.chunk_start) + record.chunk_ms > fromMs)))
    if (payload.items.length < 500) break
    const next = payload.items[payload.items.length - 1]?.id
    if (!next || next <= after) throw new Error('Destination totals pagination did not advance')
    after = next
  }
  return records
}
