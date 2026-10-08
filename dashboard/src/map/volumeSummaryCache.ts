import { parseEpoch, readActivityChunkSummaries } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import type { DestinationVolumeIndex, VolumeChunk } from './destinationVolumes'

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
    const incoming = await readActivityChunkSummaries(this.sessionId, snapshot ? 0 : this.watermark, signal, fromMs)
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
