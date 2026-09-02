import { useCallback, useEffect, useMemo, useState } from 'react'
import { useStore } from 'zustand'
import {
  selectDetailGatewayData,
  selectOverviewGatewayData,
  sessionTimelineStore,
} from '../timeline/store/sessionStore'
import { chooseLOD, sessionController } from '../timeline/transport/sessionController'
import { parseEpoch } from '../timeline/domain/time'

/** React adapter for the shared session runtime. */
export function useGatewayData(requestedSessionId?: string | null) {
  const [fallbackEpochMs] = useState(() => Date.now())
  const sessionVersion = useStore(sessionTimelineStore, (state) => state.sessionVersion)
  const overviewVersion = useStore(sessionTimelineStore, (state) => state.overviewVersion)
  const connectionState = useStore(sessionTimelineStore, (state) => state.connectionState)
  const error = useStore(sessionTimelineStore, (state) => state.error)
  const manifest = useStore(sessionTimelineStore, (state) => state.manifest)
  const liveEdgeMs = useStore(sessionTimelineStore, (state) => state.liveEdgeMs)
  const mode = useStore(sessionTimelineStore, (state) => state.mode)
  const playback = useStore(sessionTimelineStore, (state) => state.playback)
  const rate = useStore(sessionTimelineStore, (state) => state.rate)

  useEffect(() => {
    void sessionController.start(requestedSessionId ?? null)
    return () => sessionController.dispose()
  }, [requestedSessionId])

  const data = useMemo(
    () => {
      void overviewVersion
      void sessionVersion
      return selectOverviewGatewayData()
    },
    [overviewVersion, sessionVersion],
  )
  const refresh = useCallback(async () => {
    await sessionController.refresh()
  }, [])

  const epochMs = parseEpoch(manifest?.startedAt, parseEpoch(data.selectedSession?.started_at || data.selectedSession?.created, fallbackEpochMs))
  return {
    data,
    connectionState,
    error,
    refresh,
    timeline: { epochMs, liveEdgeMs, mode, playback, rate },
  }
}

export function useFlowActivityRange(
  sessionId: string | null,
  startMs: number,
  endMs: number,
  flowIds?: string[],
) {
  const detailVersion = useStore(sessionTimelineStore, (state) => state.detailVersion)
  const loadingPageCount = useStore(sessionTimelineStore, (state) => state.loadingPageKeys.size)
  const [refreshKey, setRefreshKey] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const flowIdKey = useMemo(() => Array.from(new Set(flowIds ?? [])).sort().join(','), [flowIds])
  const explicitlyEmpty = flowIds !== undefined && flowIds.length === 0
  const lod = chooseLOD(startMs, endMs)

  useEffect(() => {
    let cancelled = false
    if (!sessionId || endMs <= startMs || explicitlyEmpty) return
    const requestedFlowIDs = flowIdKey ? flowIdKey.split(',') : []
    const prefetchMs = 30_000
    sessionController.ensureDetailRange(startMs - prefetchMs, endMs + prefetchMs, requestedFlowIDs, lod)
      .then(() => {
        if (!cancelled) setError(null)
      })
      .catch((loadError: unknown) => {
        if (!cancelled && !(loadError instanceof DOMException && loadError.name === 'AbortError')) {
          setError(loadError instanceof Error ? loadError.message : 'Detailed activity is unavailable.')
        }
      })
    return () => { cancelled = true }
  }, [endMs, explicitlyEmpty, flowIdKey, lod, refreshKey, sessionId, startMs])

  const data = useMemo(
    () => {
      void detailVersion
      return explicitlyEmpty
        ? { ...selectDetailGatewayData(startMs, endMs, []), flowActivityChunks: [], flowActivityWindows: [] }
        : selectDetailGatewayData(startMs, endMs, flowIdKey ? flowIdKey.split(',') : undefined)
    },
    [detailVersion, endMs, explicitlyEmpty, flowIdKey, startMs],
  )
  const clear = useCallback(() => {
    sessionController.clearDetail()
    setRefreshKey((key) => key + 1)
    setError(null)
  }, [])

  return {
    chunks: data.flowActivityChunks,
    windows: data.flowActivityWindows,
    dnsQueries: data.dnsQueries,
    loading: !explicitlyEmpty && loadingPageCount > 0,
    error,
    clear,
  }
}
