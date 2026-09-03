import { createStore } from 'zustand/vanilla'
import type {
  GateDecision,
  GateStatus,
  PipelineDirection,
  PipelineEvent,
  PipelineEventKind,
  PipelineStreamMessage,
  ProxyLabMode,
} from '../types'

const MAX_EPHEMERAL_EVENTS = 20_000
const EPHEMERAL_RETENTION_MS = 30_000

export type ProxyLabFilters = {
  clientIps: string[]
  protocols: string[]
  kinds: PipelineEventKind[]
  directions: PipelineDirection[]
}

export type ProxyLabState = {
  sessionId: string | null
  mode: ProxyLabMode
  filters: ProxyLabFilters
  selectedEventId: string | null
  selectedTraceId: string | null
  traceConnection: 'idle' | 'connecting' | 'live' | 'reconnecting' | 'gap' | 'error'
  traceError: string | null
  ephemeralEvents: Map<string, PipelineEvent>
  ephemeralVersion: number
  oldestSequence: number | null
  newestSequence: number | null
  traceDropped: number
  gateStatus: GateStatus | null
  pendingDecisions: Map<string, GateDecision>
  pendingVersion: number
  recentDecisions: GateDecision[]
  controlInFlight: Set<string>
  controlConnection: 'idle' | 'connecting' | 'ready' | 'error'
  announcement: string
  controlError: string | null
  operatorToken: string
}

function initialState(sessionId: string | null = null): ProxyLabState {
  return {
    sessionId,
    mode: 'replay',
    filters: { clientIps: [], protocols: [], kinds: [], directions: [] },
    selectedEventId: null,
    selectedTraceId: null,
    traceConnection: 'idle',
    traceError: null,
    ephemeralEvents: new Map(),
    ephemeralVersion: 0,
    oldestSequence: null,
    newestSequence: null,
    traceDropped: 0,
    gateStatus: null,
    pendingDecisions: new Map(),
    pendingVersion: 0,
    recentDecisions: [],
    controlInFlight: new Set(),
    controlConnection: 'idle',
    announcement: '',
    controlError: null,
    operatorToken: '',
  }
}

export const proxyLabStore = createStore<ProxyLabState>()(() => initialState())

export function resetProxyLabSession(sessionId: string) {
  const version = proxyLabStore.getState().ephemeralVersion + 1
  proxyLabStore.setState({ ...initialState(sessionId), ephemeralVersion: version }, true)
}

export function clearProxyLabRoute() {
  const previous = proxyLabStore.getState()
  proxyLabStore.setState({
    ...initialState(),
    ephemeralVersion: previous.ephemeralVersion + 1,
    pendingVersion: previous.pendingVersion + 1,
  }, true)
}

export function setProxyLabMode(mode: ProxyLabMode) {
  proxyLabStore.setState({ mode, controlError: null })
}

export function setProxyLabFilters(filters: Partial<ProxyLabFilters>) {
  const state = proxyLabStore.getState()
  proxyLabStore.setState({ filters: { ...state.filters, ...filters } })
}

export function selectProxyLabEvent(eventId: string | null, traceId: string | null) {
  proxyLabStore.setState({ selectedEventId: eventId, selectedTraceId: traceId })
}

export function setTraceConnection(
  traceConnection: ProxyLabState['traceConnection'],
  traceError: string | null = null,
) {
  proxyLabStore.setState({ traceConnection, traceError })
}

export function applyTraceMessageMetadata(message: PipelineStreamMessage) {
  const state = proxyLabStore.getState()
  proxyLabStore.setState({
    oldestSequence: message.oldestSequence,
    newestSequence: message.newestSequence,
    traceDropped: Math.max(
      state.traceDropped,
      message.droppedEvents + message.ingressRejected + message.subscriberDropped + message.burstDiscarded,
    ),
  })
}

export function addEphemeralEvents(events: readonly PipelineEvent[], droppedEvents = 0) {
  if (events.length === 0 && droppedEvents === 0) return
  const state = proxyLabStore.getState()
  const next = new Map(state.ephemeralEvents)
  let newestTime = 0
  for (const event of events) {
    next.set(event.id, event)
    newestTime = Math.max(newestTime, event.occurredAtMs)
  }
  for (const event of next.values()) newestTime = Math.max(newestTime, event.occurredAtMs)
  const cutoff = newestTime - EPHEMERAL_RETENTION_MS
  const retained = Array.from(next.values())
    .filter((event) => event.occurredAtMs >= cutoff)
    .sort((left, right) => left.sequence - right.sequence || left.id.localeCompare(right.id))
    .slice(-MAX_EPHEMERAL_EVENTS)
  const sequences = retained.map((event) => event.sequence)
  proxyLabStore.setState({
    ephemeralEvents: new Map(retained.map((event) => [event.id, event])),
    ephemeralVersion: state.ephemeralVersion + 1,
    oldestSequence: sequences.length ? Math.min(...sequences) : null,
    newestSequence: sequences.length ? Math.max(...sequences) : null,
    traceDropped: state.traceDropped + Math.max(0, droppedEvents),
  })
}

export function setGateStatus(gateStatus: GateStatus | null) {
  proxyLabStore.setState({ gateStatus })
}

export function synchronizePendingDecisions(decisions: readonly GateDecision[]) {
  const state = proxyLabStore.getState()
  proxyLabStore.setState({
    pendingDecisions: new Map(decisions.map((decision) => [decision.id, decision])),
    pendingVersion: state.pendingVersion + 1,
  })
}

export function completeGateDecision(decision: GateDecision) {
  const state = proxyLabStore.getState()
  const pendingDecisions = new Map(state.pendingDecisions)
  pendingDecisions.delete(decision.id)
  proxyLabStore.setState({
    pendingDecisions,
    recentDecisions: [decision, ...state.recentDecisions.filter((item) => item.id !== decision.id)].slice(0, 12),
    pendingVersion: state.pendingVersion + 1,
    announcement: `${decision.protocol.toUpperCase()} flow ${decision.state}.`,
  })
}

export function setControlInFlight(key: string, active: boolean) {
  const state = proxyLabStore.getState()
  const controlInFlight = new Set(state.controlInFlight)
  if (active) controlInFlight.add(key)
  else controlInFlight.delete(key)
  proxyLabStore.setState({ controlInFlight })
}

export function setControlConnection(controlConnection: ProxyLabState['controlConnection']) {
  proxyLabStore.setState({ controlConnection })
}

export function setControlError(controlError: string | null) {
  proxyLabStore.setState({ controlError })
}

export function setOperatorToken(operatorToken: string) {
  proxyLabStore.setState({ operatorToken })
}
