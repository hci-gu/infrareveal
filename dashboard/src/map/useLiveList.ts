import { useCallback, useRef, useState } from 'react'
import type { FocusEvent, UIEvent } from 'react'
import { stableActivityOrder } from './activityOrder'

/** Activity lists retain ongoing lanes through brief quiet gaps. Other sorts
 * update at most once per second; inspection holds either kind of ordering. */
export function useLiveList<T extends { id: string }>(items: T[], scope: string, cursorMs: number, lastActivity?: (item: T) => number) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const attachScroll = useCallback((element: HTMLDivElement | null) => { scrollRef.current = element }, [])
  const [paused, setPaused] = useState(false)
  const tick = Math.floor(cursorMs / 1000)
  const [order, setOrder] = useState({ scope, tick: -Infinity, ids: [] as string[], activeIds: [] as string[] })
  const reset = order.scope !== scope || (!paused && tick < order.tick)
  const update = reset || (!paused && order.tick !== tick)
  const activity = update && lastActivity ? stableActivityOrder(items.map(item => ({ id: item.id, lastActivityMs: lastActivity(item) })), reset ? [] : order.activeIds, cursorMs) : null
  const ids = update ? activity?.ids ?? items.map(item => item.id) : order.ids
  if (order.scope !== scope && paused) setPaused(false)
  const byId = new Map(items.map(item => [item.id, item]))
  const ordered: T[] = []
  for (const id of ids) { const item = byId.get(id); if (item) { ordered.push(item); byId.delete(id) } }
  ordered.push(...byId.values())
  const nextIds = ordered.map(item => item.id)
  if (update || nextIds.length !== order.ids.length || nextIds.some((id, i) => order.ids[i] !== id)) setOrder({ scope, tick, ids: nextIds, activeIds: activity?.activeIds ?? order.activeIds })
  const back = () => {
    setPaused(false); setOrder({ scope, tick: -Infinity, ids: [], activeIds: [] })
    scrollRef.current?.scrollTo({ top: 0, left: 0 })
  }
  return { items: ordered, paused, scrollRef: attachScroll, pause: () => setPaused(true), back,
    // Pointer activation must finish before the Back to latest button appears.
    onFocus: (event: FocusEvent<HTMLElement>) => { if (event.target.matches(':focus-visible')) setPaused(true) },
    onScroll: (event: UIEvent<HTMLDivElement>) => { if (event.currentTarget.scrollTop > 8 || event.currentTarget.scrollLeft > 8) setPaused(true) } }
}
