import { useEffect, useMemo, useState } from 'react'
import { parseEpoch, sessionTimelineStore, timelineStartMs } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import type { VolumeChunk } from './destinationVolumes'

const defaultUrl = typeof window === 'undefined' ? 'http://127.0.0.1:8090' : `${window.location.protocol}//${window.location.hostname}:8090`
const baseUrl = (import.meta.env.VITE_POCKETBASE_URL ?? defaultUrl).replace(/\/$/, '')
const fields = 'id,session,flow,chunk_start,chunk_ms,wire_bytes_in,wire_bytes_out,capture_complete,dropped_events,updated_at_source,updated'
const noRecords: VolumeChunk[] = []
type State = { sessionId: string; records: VolumeChunk[]; loading: boolean; error: boolean }

/** Session-wide summaries only; raw packet samples stay in the bounded rate window. */
export function useDestinationVolumes(sessionId: string | null, live: boolean, ephemeral = false, fromMs = 0) {
  const [state, setState] = useState<State>({ sessionId: '', records: [], loading: true, error: false })
  useEffect(() => {
    if (!sessionId) return
    const controller = new AbortController()
    const records = new Map<string, VolumeChunk>()
    let watermark = 0
    let timer = 0
    async function refresh() {
      try {
        const cutoff = ephemeral ? timelineStartMs(sessionTimelineStore.getState()) : 0
        const incoming = await readVolumeChunks(sessionId!, ephemeral ? 0 : watermark, controller.signal, cutoff)
        // Authoritative replacement repairs deletions as well as expiring old IDs.
        if (ephemeral) records.clear()
        if (controller.signal.aborted) return
        for (const record of incoming) {
          records.set(record.id, record)
          watermark = Math.max(watermark, parseEpoch(record.updated, 0))
        }
        setState({ sessionId: sessionId!, records: [...records.values()], loading: false, error: false })
        if (live) timer = window.setTimeout(() => void refresh(), 5000)
      } catch {
        if (controller.signal.aborted) return
        setState({ sessionId: sessionId!, records: [...records.values()], loading: false, error: true })
        timer = window.setTimeout(() => void refresh(), 10_000)
      }
    }
    void refresh()
    return () => { controller.abort(); window.clearTimeout(timer) }
  }, [sessionId, live, ephemeral])
  const records = state.sessionId === sessionId ? state.records : noRecords
  const index = useMemo(() => indexDestinationVolumes(records, ephemeral ? fromMs : 0), [records, ephemeral, fromMs])
  return { index, loading: state.sessionId !== sessionId || state.loading, error: state.sessionId === sessionId && state.error }
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
