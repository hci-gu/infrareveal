import { useEffect, useMemo, useRef, useState } from 'react'
import { emptyGatewayData, getGatewayData, pb } from './pocketbaseClient'
import type { ConnectionState, DNSQuery, Destination, Flow, FlowAttribution, GatewayData, Route, Session } from './types'

type StoreMaps = {
  sessions: Map<string, Session>
  selectedSession: Session | null
  flows: Map<string, Flow>
  dnsQueries: Map<string, DNSQuery>
  attributions: Map<string, FlowAttribution>
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
  }, [requestedSessionId])

  const data = useMemo(() => dataFromMaps(maps), [maps])

  return {
    data,
    connectionState,
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
