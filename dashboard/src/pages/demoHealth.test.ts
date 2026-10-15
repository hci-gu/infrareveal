import { expect, it } from 'vitest'
import { demoHealthMessage } from './demoHealth'
import type { DemoStatus } from '@infrareveal/session-state'

it('distinguishes stale capture and failed cleanup from a healthy idle demo', () => {
  const now = Date.parse('2026-09-24T12:00:00Z')
  const status: DemoStatus = { sessionId: 'session', serverNow: new Date(now).toISOString(), enabled: true, observing: true, maintenance: {lastSuccess: new Date(now).toISOString(), lastError: ''}, capture: {running: true, confirmed_ms: now, error: '', quality:'complete', dropped:0} }
  expect(demoHealthMessage(status, now)).toBe('')
  expect(demoHealthMessage(status, now + 61_000)).toContain('cleanup')
  expect(demoHealthMessage({...status, capture: {...status.capture!, running: false}}, now)).toContain('capture')
  expect(demoHealthMessage({...status, maintenance: {...status.maintenance, lastError: 'database full'}}, now)).toContain('cleanup')
})
