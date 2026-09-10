import { describe, expect, it } from 'vitest'
import type { Session, SessionManifest } from '@infrareveal/session-state'
import { auditQuality, filterSessions, sessionDuration, summaryCount } from './sessionSummaries'
const session = (id: string, active = false): Session => ({ id, name: id, active, created: '2026-09-07T10:00:00Z', updated: '2026-09-07T10:00:00Z', started_at: '2026-09-07T10:00:00Z', ended_at: active ? undefined : '2026-09-07T10:01:02Z' })
const manifest: SessionManifest = { sessionId: 'a', name: 'a', startedAt: '2026-09-07T10:00:00Z', endedAt: null, active: true, serverNow: '2026-09-07T10:05:00Z', watermark: '', counts: { flows: 0, dns_queries: 8 }, coverage: { from: '', to: '' } }
describe('session source summaries', () => {
  it('distinguishes a measured zero from an absent or fallback count', () => {
    expect(summaryCount(manifest, 'flows')).toBe(0)
    expect(summaryCount(manifest, 'routes')).toBeNull()
    expect(summaryCount({ ...manifest, transport: 'collections' }, 'flows')).toBeNull()
    expect(summaryCount(undefined, 'flows')).toBeNull()
  })
  it('keeps unknown audit state and manifest overrides explicit', () => {
    expect(auditQuality(session('a'))).toBe('Unknown')
    expect(auditQuality({ ...session('a'), gate_audit_complete: true }, { ...manifest, gateAuditComplete: false })).toBe('Incomplete')
  })
  it('uses a synchronized server clock for live elapsed time and a fixed end for recordings', () => {
    expect(sessionDuration(session('a', true))).toBeNull()
    expect(sessionDuration(session('a', true), manifest, 1000, 6000)).toBe(305)
    expect(sessionDuration(session('a'), undefined, undefined, 999999)).toBe(62)
  })
  it('retains every active source and sorts equal dates deterministically', () => {
    const sources = [session('b', true), session('a', true), session('c')]
    expect(filterSessions(sources, 'live', '').map(s => s.id)).toEqual(['a', 'b'])
    expect(filterSessions(sources, 'recorded', '').map(s => s.id)).toEqual(['c'])
    expect(filterSessions(sources, 'all', ' B ').map(s => s.id)).toEqual(['b'])
  })
})
