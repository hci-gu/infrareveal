import { emptyGatewayData } from './sessionData'
import { coalescedSelector, stableGatewayData } from './displayUpdates'
import type { SessionTimelineState } from '../timeline/store/sessionStore'
import { useCallback, useEffect, useMemo, useState, useId, useSyncExternalStore } from 'react'
import { useStore } from 'zustand'
import {
  selectDetailGatewayData,
  selectOverviewGatewayData,
  sessionTimelineStore,
  timelineStartMs,
} from '../timeline/store/sessionStore'
import { chooseLOD, sessionController } from '../timeline/transport/sessionController'
import { parseEpoch } from '../timeline/domain/time'

const emptyActivity = emptyGatewayData()

function useDisplayVersion(kind: 'overview' | 'detail', intervalMs: number) {
  const source = useMemo(() => coalescedSelector(sessionTimelineStore,
    (state: SessionTimelineState) => `${state.selectedSessionId}:${state.sessionVersion}:${kind === 'overview' ? state.overviewVersion : state.detailVersion}`,
    state => state.selectedSessionId, intervalMs), [kind, intervalMs])
  return useSyncExternalStore(source.subscribe, source.getSnapshot, source.getSnapshot)
}

/** React adapter for the shared session runtime. */
export function useGatewayData(requestedSessionId?: string | null, enabled = true, publishIntervalMs = 0) {
  const [fallbackEpochMs] = useState(() => Date.now())
  const overviewVersion = useDisplayVersion('overview', publishIntervalMs)
  const stabilize = useMemo(() => stableGatewayData(), [])
  const connectionState = useStore(sessionTimelineStore, (state) => state.connectionState)
  const error = useStore(sessionTimelineStore, (state) => state.error)
  const manifest = useStore(sessionTimelineStore, (state) => state.manifest)
  const liveEdgeMs = useStore(sessionTimelineStore, (state) => state.liveEdgeMs)
  const mode = useStore(sessionTimelineStore, (state) => state.mode)
  const playback = useStore(sessionTimelineStore, (state) => state.playback)
  const rate = useStore(sessionTimelineStore, (state) => state.rate)

  useEffect(() => {
    if (!enabled) return
    void sessionController.start(requestedSessionId ?? null)
    return () => sessionController.dispose()
  }, [enabled, requestedSessionId])

  const data = useMemo(
    () => {
      void overviewVersion
      return stabilize(selectOverviewGatewayData())
    },
    [overviewVersion, stabilize],
  )
  const refresh = useCallback(async () => {
    if (enabled) await sessionController.refresh()
  }, [enabled])

  const epochMs = manifest ? timelineStartMs() : parseEpoch(undefined, parseEpoch(data.selectedSession?.started_at || data.selectedSession?.created, fallbackEpochMs))
  return {
    data,
    connectionState,
    error,
    refresh,
    timeline: { epochMs, liveEdgeMs, mode, playback, rate, manifest },
  }
}

export function useFlowActivityRange(
  sessionId: string | null,
  startMs: number,
  endMs: number,
  flowIds?: string[],
  publishIntervalMs = 0,
  enabled = true,
) {
  const detailVersion = useDisplayVersion('detail', publishIntervalMs)
  const stabilize = useMemo(() => stableGatewayData(), [])
  const loadingPageCount = useStore(sessionTimelineStore, (state) => state.loadingPageKeys.size)
  const owner = useId()
  const [refreshKey, setRefreshKey] = useState(0)
  const [error, setError] = useState<string | null>(null)
  const [completedRequest, setCompletedRequest] = useState<string | null>(null)
  const flowIdKey = useMemo(() => Array.from(new Set(flowIds ?? [])).sort().join(','), [flowIds])
  const explicitlyEmpty = flowIds !== undefined && flowIds.length === 0
  const lod = chooseLOD(startMs, endMs)
  const requestKey = JSON.stringify([sessionId, startMs, endMs, flowIdKey, lod, refreshKey])

  useEffect(() => {
    let cancelled = false
    if (!enabled || !sessionId || endMs <= startMs || explicitlyEmpty) return
    const requestedFlowIDs = flowIdKey ? flowIdKey.split(',') : []
    const prefetchMs = 30_000
    sessionController.ensureDetailRange(startMs - prefetchMs, endMs + prefetchMs, requestedFlowIDs, lod, owner)
      .then(() => {
        if (!cancelled) { setError(null); setCompletedRequest(requestKey) }
      })
      .catch((loadError: unknown) => {
        if (!cancelled && !(loadError instanceof DOMException && loadError.name === 'AbortError')) {
          setError(loadError instanceof Error ? loadError.message : 'Detailed activity is unavailable.')
        }
      })
    return () => { cancelled = true; sessionController.releaseDetailRange(owner) }
  }, [enabled, endMs, explicitlyEmpty, flowIdKey, lod, owner, refreshKey, requestKey, sessionId, startMs])

  const data = useMemo(
    () => {
      void detailVersion
      if (!enabled || !sessionId) return emptyActivity
      return stabilize(explicitlyEmpty
        ? { ...selectDetailGatewayData(startMs, endMs, []), flowActivityChunks: [], flowActivityWindows: [] }
        : selectDetailGatewayData(startMs, endMs, flowIdKey ? flowIdKey.split(',') : undefined))
    },
    [enabled, sessionId, detailVersion, endMs, explicitlyEmpty, flowIdKey, startMs, stabilize],
  )
  const clear = useCallback(() => {
    sessionController.clearDetail()
    setRefreshKey((key) => key + 1)
    setError(null)
  }, [])

  return {
    routes: data.routes,
    chunks: data.flowActivityChunks,
    windows: data.flowActivityWindows,
    dnsQueries: data.dnsQueries,
    gateEvents: data.gateEvents,
    loading: enabled && !explicitlyEmpty && loadingPageCount > 0,
    loaded: Boolean(enabled && sessionId && !explicitlyEmpty && completedRequest === requestKey && loadingPageCount === 0 && !error),
    error,
    clear,
  }
}
