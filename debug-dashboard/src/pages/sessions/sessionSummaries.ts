import type { Session, SessionManifest } from '@infrareveal/session-state'

export type SessionCategory = 'all' | 'live' | 'recorded'
export function filterSessions(sessions: readonly Session[], category: SessionCategory, query: string) {
  const search = query.toLocaleLowerCase().trim()
  return sessions.filter(session => (category === 'all' || session.active === (category === 'live')) &&
    `${session.name} ${session.id} ${new Date(session.started_at || session.created).toLocaleString()}`.toLocaleLowerCase().includes(search))
    .sort((a, b) => Date.parse(b.started_at || b.created) - Date.parse(a.started_at || a.created) || a.id.localeCompare(b.id))
}
export function summaryCount(manifest: SessionManifest | undefined, field: string): number | null {
  const count = manifest?.transport === 'collections' ? undefined : manifest?.counts[field]
  return typeof count === 'number' && Number.isFinite(count) && count >= 0 ? count : null
}
export function auditQuality(session: Session, manifest?: SessionManifest) {
  const complete = manifest?.gateAuditComplete ?? session.gate_audit_complete
  return complete === true ? 'Complete' : complete === false ? 'Incomplete' : 'Unknown'
}
export function sessionDuration(session: Session, manifest?: SessionManifest, receivedAt?: number, now = Date.now()) {
  const start = Date.parse(manifest?.startedAt || session.started_at || session.created)
  const end = session.active
    ? manifest && receivedAt ? Date.parse(manifest.serverNow) + Math.max(0, now - receivedAt) : NaN
    : Date.parse(manifest?.endedAt || session.ended_at || '')
  return Number.isFinite(start) && Number.isFinite(end) ? Math.max(0, end - start) / 1000 : null
}
