import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import { emptyGatewayData, getFlowActivityRange, getGatewayData, pb } from './pocketbaseClient'
import type { ActivityEpisode, ConnectionState, DNSQuery, Destination, Flow, FlowActivityChunk, FlowActivityStatus, FlowActivityWindow, FlowAssociation, FlowAttribution, GatewayData, Route, Session } from './types'

type StoreMaps = {
  sessions: Map<string, Session>
  selectedSession: Session | null
  flows: Map<string, Flow>
  dnsQueries: Map<string, DNSQuery>
  attributions: Map<string, FlowAttribution>
  activityEpisodes: Map<string, ActivityEpisode>
  flowAssociations: Map<string, FlowAssociation>
  flowActivityStatuses: Map<string, FlowActivityStatus>
  destinations: Map<string, Destination>
  routes: Map<string, Route>
}

type RealtimeEvent<T> = {
  action: string
  record: T
}

function mapsFromData(data: GatewayData): StoreMaps {
  return {
    sessions: new Map(data.sessions.map((item) => [item.id, item])),
    selectedSession: data.selectedSession,
    flows: new Map(data.flows.map((item) => [item.id, item])),
    dnsQueries: new Map(data.dnsQueries.map((item) => [item.id, item])),
    attributions: new Map(data.attributions.map((item) => [item.id, item])),
    activityEpisodes: new Map(data.activityEpisodes.map((item) => [item.id, item])),
    flowAssociations: new Map(data.flowAssociations.map((item) => [item.id, item])),
    flowActivityStatuses: new Map(data.flowActivityStatuses.map((item) => [item.id, item])),
    destinations: new Map(data.destinations.map((item) => [item.id, item])),
    routes: new Map(data.routes.map((item) => [item.id, item])),
  }
}

function dataFromMaps(maps: StoreMaps): GatewayData {
  const sessions = Array.from(maps.sessions.values()).sort(sortSessions)
  return {
    sessions,
    selectedSession: maps.selectedSession,
    flows: Array.from(maps.flows.values()),
    dnsQueries: Array.from(maps.dnsQueries.values()),
    attributions: Array.from(maps.attributions.values()),
    activityEpisodes: Array.from(maps.activityEpisodes.values()),
    flowAssociations: Array.from(maps.flowAssociations.values()),
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: Array.from(maps.flowActivityStatuses.values()),
    destinations: Array.from(maps.destinations.values()),
    routes: Array.from(maps.routes.values()),
  }
}

function applyRealtimeRecord<T extends { id: string }>(
  current: Map<string, T>,
  event: RealtimeEvent<T>,
) {
  const next = new Map(current)
  if (event.action === 'delete') {
    next.delete(event.record.id)
  } else {
    next.set(event.record.id, event.record)
  }
  return next
}

export function useGatewayData(requestedSessionId?: string | null) {
  const [maps, setMaps] = useState<StoreMaps>(() => mapsFromData(emptyGatewayData()))
  const [connectionState, setConnectionState] = useState<ConnectionState>('loading')
  const [error, setError] = useState<string | null>(null)
  const [refreshKey, setRefreshKey] = useState(0)
  const connectionStateRef = useRef<ConnectionState>('loading')
  const selectedSessionIdRef = useRef<string | null>(null)
  const requestedSessionIdRef = useRef<string | null>(requestedSessionId ?? null)

  useEffect(() => {
    requestedSessionIdRef.current = requestedSessionId ?? null
  }, [requestedSessionId])

  useEffect(() => {
    let cancelled = false
    let fallbackTimer = 0
    const unsubscribers: Array<() => void> = []

    async function refresh(nextState: ConnectionState) {
      try {
        const data = await getGatewayData(requestedSessionIdRef.current)
        if (!cancelled) {
          selectedSessionIdRef.current = data.selectedSession?.id ?? null
          setMaps(mapsFromData(data))
          connectionStateRef.current = nextState
          setConnectionState(nextState)
          setError(null)
        }
      } catch (loadError) {
        if (!cancelled) {
          connectionStateRef.current = 'error'
          setConnectionState('error')
          setError(normalizeLoadError(loadError))
        }
      }
    }

    async function subscribe() {
      try {
        const [
          unsubscribeSessions,
          unsubscribeFlows,
          unsubscribeDNS,
          unsubscribeAttributions,
          unsubscribeActivityEpisodes,
          unsubscribeFlowAssociations,
          unsubscribeFlowActivityStatuses,
          unsubscribeDestinations,
          unsubscribeRoutes,
        ] = await Promise.all([
          pb.collection('sessions').subscribe('*', (event: RealtimeEvent<Session>) => {
            setMaps((current) => {
              const sessions = applyRealtimeRecord(current.sessions, event)
              const nextSelectedSession = resolveSelectedSession(
                Array.from(sessions.values()),
                requestedSessionIdRef.current,
                current.selectedSession,
              )
              selectedSessionIdRef.current = nextSelectedSession?.id ?? null
              return { ...current, sessions, selectedSession: nextSelectedSession }
            })

            if (!requestedSessionIdRef.current && event.record.active) {
              refresh('live')
            }
          }),
          pb.collection('flows').subscribe('*', (event: RealtimeEvent<Flow>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({ ...current, flows: applyRealtimeRecord(current.flows, event) }))
          }),
          pb.collection('dns_queries').subscribe('*', (event: RealtimeEvent<DNSQuery>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({ ...current, dnsQueries: applyRealtimeRecord(current.dnsQueries, event) }))
          }),
          pb.collection('flow_attributions').subscribe('*', (event: RealtimeEvent<FlowAttribution>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({
              ...current,
              attributions: applyRealtimeRecord(current.attributions, event),
            }))
          }),
          pb.collection('activity_episodes').subscribe('*', (event: RealtimeEvent<ActivityEpisode>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({
              ...current,
              activityEpisodes: applyRealtimeRecord(current.activityEpisodes, event),
            }))
          }),
          pb.collection('flow_associations').subscribe('*', (event: RealtimeEvent<FlowAssociation>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({
              ...current,
              flowAssociations: applyRealtimeRecord(current.flowAssociations, event),
            }))
          }),
          pb.collection('flow_activity_status').subscribe('*', (event: RealtimeEvent<FlowActivityStatus>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({
              ...current,
              flowActivityStatuses: applyRealtimeRecord(current.flowActivityStatuses, event),
            }))
          }),
          pb.collection('destinations').subscribe('*', (event: RealtimeEvent<Destination>) => {
            setMaps((current) => ({
              ...current,
              destinations: applyRealtimeRecord(current.destinations, event),
            }))
          }),
          pb.collection('routes').subscribe('*', (event: RealtimeEvent<Route>) => {
            if (!belongsToSelectedSession(event.record, selectedSessionIdRef.current)) {
              return
            }
            setMaps((current) => ({ ...current, routes: applyRealtimeRecord(current.routes, event) }))
          }),
        ])

        unsubscribers.push(
          unsubscribeSessions,
          unsubscribeFlows,
          unsubscribeDNS,
          unsubscribeAttributions,
          unsubscribeActivityEpisodes,
          unsubscribeFlowAssociations,
          unsubscribeFlowActivityStatuses,
          unsubscribeDestinations,
          unsubscribeRoutes,
        )
        if (!cancelled) {
          connectionStateRef.current = 'live'
          setConnectionState('live')
        }
      } catch {
        if (!cancelled) {
          connectionStateRef.current = 'polling'
          setConnectionState('polling')
        }
      }
    }

    refresh('polling')
    subscribe()
    fallbackTimer = window.setInterval(() => {
      refresh(connectionStateRef.current === 'live' ? 'live' : 'polling')
    }, 10000)

    return () => {
      cancelled = true
      window.clearInterval(fallbackTimer)
      for (const unsubscribe of unsubscribers) {
        unsubscribe()
      }
    }
  }, [requestedSessionId, refreshKey])

  const data = useMemo(() => dataFromMaps(maps), [maps])
  const refresh = useCallback(() => setRefreshKey((key) => key + 1), [])

  return {
    data,
    connectionState,
    error,
    refresh,
  }
}

export function useFlowActivityRange(
  sessionId: string | null,
  startMs: number,
  endMs: number,
) {
  const [chunks, setChunks] = useState<Map<string, FlowActivityChunk>>(new Map())
  const [windows, setWindows] = useState<Map<string, FlowActivityWindow>>(new Map())
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    let cancelled = false
    let pollTimer = 0
    const unsubscribers: Array<() => void> = []

    const inRange = (timestamp: string) => {
      const value = Date.parse(timestamp)
      return Number.isFinite(value) && value >= startMs - 60_000 && value < endMs
    }
    const belongs = (record: { session: string }) => record.session === sessionId

    async function load() {
      if (!sessionId || endMs <= startMs) {
        setChunks(new Map())
        setWindows(new Map())
        setError(null)
        return
      }
      try {
        const result = await getFlowActivityRange(sessionId, startMs, endMs)
        if (!cancelled) {
          setChunks(new Map(result.chunks.map((item) => [item.id, item])))
          setWindows(new Map(result.windows.map((item) => [item.id, item])))
          setError(null)
        }
      } catch (loadError) {
        if (!cancelled) setError(normalizeLoadError(loadError))
      }
    }

    async function subscribe() {
      if (!sessionId) return
      try {
        const [unsubscribeChunks, unsubscribeWindows] = await Promise.all([
          pb.collection('flow_activity_chunks').subscribe('*', (event: RealtimeEvent<FlowActivityChunk>) => {
            if (!belongs(event.record) || !inRange(event.record.chunk_start)) return
            setChunks((current) => applyRealtimeRecord(current, event))
          }),
          pb.collection('flow_activity_windows').subscribe('*', (event: RealtimeEvent<FlowActivityWindow>) => {
            if (!belongs(event.record) || !inRange(event.record.window_start)) return
            setWindows((current) => applyRealtimeRecord(current, event))
          }),
        ])
        unsubscribers.push(unsubscribeChunks, unsubscribeWindows)
      } catch {
        // The polling fallback below keeps this bounded range fresh.
      }
    }

    load()
    subscribe()
    pollTimer = window.setInterval(load, 10000)
    return () => {
      cancelled = true
      window.clearInterval(pollTimer)
      for (const unsubscribe of unsubscribers) unsubscribe()
    }
  }, [endMs, sessionId, startMs])

  return {
    chunks: useMemo(() => Array.from(chunks.values()), [chunks]),
    windows: useMemo(() => Array.from(windows.values()), [windows]),
    error,
  }
}

function normalizeLoadError(error: unknown) {
  const message = error instanceof Error ? error.message : ''
  if (!message || message === 'Something went wrong.') {
    return 'PocketBase is unavailable; showing the current cached session.'
  }
  return message
}

function belongsToSelectedSession(record: { session?: string }, selectedSessionId: string | null) {
  return !selectedSessionId || record.session === selectedSessionId
}

function resolveSelectedSession(
  sessions: Session[],
  requestedSessionId: string | null,
  current: Session | null,
) {
  if (requestedSessionId) {
    return sessions.find((session) => session.id === requestedSessionId) ?? current
  }
  return sessions.find((session) => session.active) ?? current ?? sessions.sort(sortSessions)[0] ?? null
}

function sortSessions(left: Session, right: Session) {
  if (left.active !== right.active) {
    return left.active ? -1 : 1
  }
  return new Date(right.created).getTime() - new Date(left.created).getTime()
}
