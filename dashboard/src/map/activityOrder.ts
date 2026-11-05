export type ActivityOrder = 'latest' | 'volume' | 'name'
export const ACTIVITY_HOLD_MS = 15_000
type ActivityItem = { id: string; label: string; bytes: number; lastActivityMs: number }

/** Packet timing must not shuffle ongoing traffic. Keep the active group in
 * place, admit new/returning lanes by recency, and demote only after a quiet gap.
 * Sustained lanes rise as the lanes ahead of them become quiet. */
export function stableActivityOrder(items: Pick<ActivityItem, 'id' | 'lastActivityMs'>[], previousActive: string[], cursorMs: number) {
  const recent = [...items].sort((a, b) => b.lastActivityMs - a.lastActivityMs || a.id.localeCompare(b.id))
  const active = new Set(recent.filter(item => item.lastActivityMs > 0 && item.lastActivityMs <= cursorMs && cursorMs - item.lastActivityMs < ACTIVITY_HOLD_MS).map(item => item.id))
  const retained = previousActive.filter(id => active.has(id))
  const retainedSet = new Set(retained)
  const activeIds = [...retained, ...recent.filter(item => active.has(item.id) && !retainedSet.has(item.id)).map(item => item.id)]
  return { ids: [...activeIds, ...recent.filter(item => !active.has(item.id)).map(item => item.id)], activeIds }
}

export function compareActivity(order: ActivityOrder) {
  return (a: ActivityItem, b: ActivityItem) => {
    const primary = order === 'latest' ? b.lastActivityMs - a.lastActivityMs : order === 'volume' ? b.bytes - a.bytes : a.label.localeCompare(b.label)
    return primary || a.id.localeCompare(b.id)
  }
}
