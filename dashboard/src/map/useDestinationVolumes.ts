import { useEffect, useMemo, useState } from 'react'
import { pb, sessionTimelineStore, timelineStartMs } from '@infrareveal/session-state'
import type { DestinationVolumeIndex, VolumeChunk } from './destinationVolumes'
import { VolumeSummaryCache } from './volumeSummaryCache'
export { readVolumeChunks } from './volumeSummaryCache'

const emptyIndex: DestinationVolumeIndex = new Map()
type State = { sessionId: string; index: DestinationVolumeIndex; loading: boolean; error: boolean }

/** Compact incremental summaries, with SSE deletion repair and a periodic snapshot. */
export function useDestinationVolumes(sessionId: string | null, live: boolean, ephemeral = false, fromMs = 0) {
  const [state, setState] = useState<State>({ sessionId: '', index: emptyIndex, loading: true, error: false })
  useEffect(() => {
    if (!sessionId) return
    const controller = new AbortController()
    const cache = new VolumeSummaryCache(sessionId)
    let timer = 0
    let unsubscribe: (() => void) | undefined
    function publish(error = false) {
      if (controller.signal.aborted) return
      setState(previous => previous.sessionId === sessionId && previous.index === cache.index && !previous.loading && previous.error === error
        ? previous : { sessionId: sessionId!, index: cache.index, loading: false, error })
    }
    if (live) void pb.collection('flow_activity_chunks').subscribe<VolumeChunk>('*', event => {
      if (event.action === 'delete' && event.record.session === sessionId) { cache.delete(event.record.id); publish() }
    }).then(stop => { if (controller.signal.aborted) stop(); else unsubscribe = stop }).catch(() => { /* Snapshots also repair missed deletions. */ })
    async function refresh() {
      try {
        const cutoff = ephemeral ? timelineStartMs(sessionTimelineStore.getState()) : 0
        await cache.refresh(controller.signal, cutoff)
        publish()
        if (live && !controller.signal.aborted) timer = window.setTimeout(() => void refresh(), 5000)
      } catch {
        if (controller.signal.aborted) return
        publish(true)
        timer = window.setTimeout(() => void refresh(), 10_000)
      }
    }
    void refresh()
    return () => { controller.abort(); window.clearTimeout(timer); unsubscribe?.() }
  }, [sessionId, live, ephemeral])
  const source = state.sessionId === sessionId ? state.index : emptyIndex
  const cutoff = ephemeral ? fromMs : 0
  // Moving the cutoff shares every flow's prefix sums; no history is parsed or sorted.
  const index = useMemo(() => {
    if (!cutoff) return source
    const view: DestinationVolumeIndex = new Map(source)
    view.fromMs = cutoff
    return view
  }, [source, cutoff])
  return { index, loading: state.sessionId !== sessionId || state.loading, error: state.sessionId === sessionId && state.error }
}
