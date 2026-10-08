import type { GraphNodeId } from '../model/graphLayout'
import { createStore } from 'zustand/vanilla'
import type {
  GateDecision,
  GateStatus,
  PipelineEvent,
  PipelineStreamMessage,
} from '../types'

const MAX_EPHEMERAL_EVENTS = 20_000
const EPHEMERAL_RETENTION_MS = 30_000

export type ProxyLabState = {
  sessionId: string | null
  observationMode: 'replay' | 'live-observe'
  requestedGateMode: 'flow' | 'strict' | 'dns'
  selectedNodeId: GraphNodeId | null
  selectedEventId: string | null
  selectedTraceId: string | null
  traceConnection: 'idle' | 'connecting' | 'live' | 'reconnecting' | 'gap' | 'error'
  traceError: string | null
  ephemeralEvents: Map<string, PipelineEvent>
  traceDropped: number
  gateStatus: GateStatus | null
  pendingDecisions: Map<string, GateDecision>
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
    observationMode: 'replay',
    requestedGateMode: 'flow',
    selectedNodeId: null,
    selectedEventId: null,
    selectedTraceId: null,
    traceConnection: 'idle',
    traceError: null,
    ephemeralEvents: new Map(),
    traceDropped: 0,
    gateStatus: null,
    pendingDecisions: new Map(),
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
  proxyLabStore.setState(initialState(sessionId), true)
}

export function clearProxyLabRoute() {
  proxyLabStore.setState(initialState(), true)
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
  proxyLabStore.setState({
    ephemeralEvents: new Map(retained.map((event) => [event.id, event])),
    traceDropped: state.traceDropped + Math.max(0, droppedEvents),
  })
}

export function setGateStatus(gateStatus: GateStatus | null) {
  proxyLabStore.setState({ gateStatus })
}

export function synchronizePendingDecisions(decisions: readonly GateDecision[]) {
  proxyLabStore.setState({
    pendingDecisions: new Map(decisions.map((decision) => [decision.id, decision])),
  })
}

export function completeGateDecision(decision: GateDecision) {
  const state = proxyLabStore.getState()
  const pendingDecisions = new Map(state.pendingDecisions)
  pendingDecisions.delete(decision.id)
  proxyLabStore.setState({
    pendingDecisions,
    recentDecisions: [decision, ...state.recentDecisions.filter((item) => item.id !== decision.id)].slice(0, 12),
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

export function setLabObservationMode(observationMode: 'replay' | 'live-observe') {
  proxyLabStore.setState({ observationMode })
}
export function setLabGateMode(requestedGateMode: 'flow' | 'strict' | 'dns') {
  proxyLabStore.setState({ requestedGateMode })
}
export function selectLabNode(selectedNodeId: GraphNodeId | null) {
  proxyLabStore.setState({ selectedNodeId })
}
