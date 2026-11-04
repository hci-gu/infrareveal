export type ActivityOrder = 'latest' | 'volume' | 'name'
type ActivityItem = { id: string; label: string; bytes: number; lastActivityMs: number }

export function compareActivity(order: ActivityOrder) {
  return (a: ActivityItem, b: ActivityItem) => {
    const primary = order === 'latest' ? b.lastActivityMs - a.lastActivityMs : order === 'volume' ? b.bytes - a.bytes : a.label.localeCompare(b.label)
    return primary || a.id.localeCompare(b.id)
  }
}
