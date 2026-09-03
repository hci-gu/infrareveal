import type { Session } from '@infrareveal/session-state'

export function partitionSessions(sessions: Session[]) {
  return {
    active: sessions.filter((session) => session.active),
    recorded: sessions.filter((session) => !session.active),
  }
}
