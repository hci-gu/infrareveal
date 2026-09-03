import { beforeEach, describe, expect, it } from 'vitest'
import type { PipelineEvent } from '../types'
import {
  addEphemeralEvents,
  clearProxyLabRoute,
  proxyLabStore,
  resetProxyLabSession,
  setOperatorToken,
  synchronizePendingDecisions,
} from './proxyLabStore'

beforeEach(() => clearProxyLabRoute())

describe('proxyLabStore', () => {
  it('caps ephemeral state by time without losing pending gate decisions', () => {
    synchronizePendingDecisions([{
      id: 'decision', flowKey: 'flow', sessionId: 'session', clientIp: '10.0.0.1', remoteIp: '1.1.1.1',
      clientPort: 5000, remotePort: 443, protocol: 'tcp', packetCount: 1, tcpFlags: 2,
      queuedAtMs: 1, deadlineMs: 10_000, state: 'queued',
    }])
    addEphemeralEvents([event('old', 1, 1), event('new', 40_000, 2)])
    expect(Array.from(proxyLabStore.getState().ephemeralEvents.keys())).toEqual(['new'])
    expect(proxyLabStore.getState().pendingDecisions.has('decision')).toBe(true)
  })

  it('clears token, control errors, and experiment state on route teardown', () => {
    resetProxyLabSession('session')
    setOperatorToken('secret')
    proxyLabStore.setState({ controlError: 'failure' })
    clearProxyLabRoute()
    expect(proxyLabStore.getState()).toMatchObject({ sessionId: null, operatorToken: '', controlError: null })
  })
})

function event(id: string, occurredAtMs: number, sequence: number): PipelineEvent {
  return {
    id, sequence, sessionId: 'session', traceId: id, kind: 'health', stage: 'health',
    occurredAtMs, timing: 'observed', summary: {},
  }
}
