import { useEffect, useMemo, useRef, useState } from 'react'
import { useStore } from 'zustand'
import { sessionTimelineStore } from '@infrareveal/session-state'
import { GateAPIError, GateClient, type StrictTuple } from '../data/gateClient'
import { completeGateDecision, proxyLabStore, setControlConnection, setControlError, setControlInFlight, setGateStatus, synchronizePendingDecisions } from './proxyLabStore'
import type { GateDecision, GateStatus } from '../types'

export function canDecide(decision: GateDecision, nowMs: number, sessionId: string, ready: boolean, inFlight: ReadonlySet<string>): boolean {
  return ready && decision.sessionId === sessionId && decision.state === 'queued' && decision.deadlineMs > nowMs && inFlight.size === 0
}
export function useLabControl(sessionId: string, enabled: boolean, baseUrl: string) {
  const token = useStore(proxyLabStore, state => state.operatorToken)
  const client = useMemo(() => new GateClient(token, baseUrl), [baseUrl, token])
  const scope = useRef<AbortController | null>(null)
  const [nowMs, setNowMs] = useState(() => Date.now())
  useEffect(() => {
    const controller = new AbortController(); scope.current = controller
    if (!enabled) { setControlConnection('idle'); setGateStatus(null); synchronizePendingDecisions([]); return () => controller.abort() }
    let loading = false
    const poll = async () => {
      if (loading || controller.signal.aborted) return
      loading = true
      try {
        const status = await client.status(controller.signal)
        const decisions = token && status.armed && status.sessionId === sessionId ? await client.pending(controller.signal) : []
        if (controller.signal.aborted) return
        setGateStatus(status); synchronizePendingDecisions(decisions); setControlConnection('ready'); setControlError(null)
      } catch (error) {
        if (!controller.signal.aborted) { setControlConnection('error'); setControlError(error instanceof Error ? error.message : 'Control unavailable') }
      } finally { loading = false }
    }
    setControlConnection('connecting'); void poll()
    const interval = setInterval(() => void poll(), 3000)
    const clock = setInterval(() => setNowMs(controlNow()), 200)
    return () => { controller.abort(); clearInterval(interval); clearInterval(clock) }
  }, [client, enabled, sessionId, token])
  const ready = () => {
    const state = proxyLabStore.getState()
    return enabled && Boolean(token) && state.sessionId === sessionId && state.controlConnection === 'ready' && state.controlInFlight.size === 0 && !scope.current?.signal.aborted
  }
  const reconcile = async (signal: AbortSignal) => {
    const status = await client.status(signal)
    const pending = status.armed && status.sessionId === sessionId ? await client.pending(signal) : []
    if (signal.aborted) return
    setGateStatus(status); synchronizePendingDecisions(pending); setControlConnection('ready')
  }
  const command = async (key: string, run: (signal: AbortSignal) => Promise<GateStatus>) => {
    const controller = scope.current
    if (!controller || !ready()) return
    setControlInFlight(key, true); setControlError(null)
    try {
      const status = await run(controller.signal)
      if (controller.signal.aborted) return
      setGateStatus(status); await reconcile(controller.signal)
    } catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof GateAPIError && error.status === 409) await reconcile(controller.signal).catch(() => undefined)
      if (!controller.signal.aborted) { setControlError(error instanceof Error ? error.message : 'Control command failed'); if (!(error instanceof GateAPIError)) setControlConnection('error') }
    } finally { if (!controller.signal.aborted) setControlInFlight(key, false) }
  }
  const decide = async (id: string, verdict: 'accept' | 'drop') => {
    const controller = scope.current, state = proxyLabStore.getState(), decision = state.pendingDecisions.get(id)
    if (!controller || !decision || !canDecide(decision, controlNow(), sessionId, ready() && state.gateStatus?.sessionId === sessionId && Boolean(state.gateStatus.armed), state.controlInFlight)) return
    setControlInFlight(`decision:${id}`, true); setControlError(null)
    try {
      const response = await client.decide(id, verdict, 'operator', controller.signal)
      if (controller.signal.aborted) return
      completeGateDecision(response.result); await reconcile(controller.signal)
    } catch (error) {
      if (controller.signal.aborted) return
      if (error instanceof GateAPIError && error.status === 409) await reconcile(controller.signal).catch(() => undefined)
      if (!controller.signal.aborted) { setControlError(error instanceof Error ? error.message : 'Decision failed'); if (!(error instanceof GateAPIError)) setControlConnection('error') }
    } finally { if (!controller.signal.aborted) setControlInFlight(`decision:${id}`, false) }
  }
  return {
    nowMs,
    arm: (clientIps: string[], mode: 'flow' | 'strict' | 'dns', strict?: StrictTuple) => command('arm', signal => client.arm({ sessionId, clientIps, mode, strict }, signal)),
    pause: () => command('pause', signal => client.pause(signal)), resume: () => command('resume', signal => client.resume(signal)),
    drain: () => command('drain', signal => client.drain(signal)), disarm: () => command('disarm', signal => client.disarm(signal)),
    acceptNext: (count: number) => command('accept-next', signal => client.acceptNext(count, 'operator', signal)),
    approveAll: () => command('approve-all', async signal => {
      const pending = [...proxyLabStore.getState().pendingDecisions.values()].filter(d => d.state === 'queued' && d.deadlineMs > controlNow())
      const response = await client.approveAll(pending.length, 'operator', signal)
      if (!signal.aborted) response.results.forEach(completeGateDecision)
      return response.status
    }), decide,
  }
}

function controlNow() {
  const { serverClock } = sessionTimelineStore.getState()
  return serverClock.serverNowMs > 0 ? serverClock.serverNowMs + Math.max(0, performance.now() - serverClock.syncedAtMs) : Date.now()
}
