import { useCallback, useRef, useState } from 'react'
import type { UIEvent } from 'react'

/** Reorder at most once per second, and hold the reader's place while inspecting history. */
export function useLiveList<T extends { id: string }>(items: T[], scope: string, cursorMs: number) {
  const scrollRef = useRef<HTMLDivElement>(null)
  const attachScroll = useCallback((element: HTMLDivElement | null) => { scrollRef.current = element }, [])
  const [paused, setPaused] = useState(false)
  const tick = Math.floor(cursorMs / 1000)
  const [order, setOrder] = useState({ scope, tick, ids: items.map(item => item.id) })
  const reset = order.scope !== scope
  const ids = reset || (!paused && order.tick !== tick) ? items.map(item => item.id) : order.ids
  if (reset && paused) setPaused(false)
  const byId = new Map(items.map(item => [item.id, item]))
  const ordered: T[] = []
  for (const id of ids) { const item = byId.get(id); if (item) { ordered.push(item); byId.delete(id) } }
  ordered.push(...byId.values())
  const nextIds = ordered.map(item => item.id)
  if (reset || (!paused && order.tick !== tick) || nextIds.length !== order.ids.length || nextIds.some((id, i) => order.ids[i] !== id)) setOrder({ scope, tick, ids: nextIds })
  const back = () => {
    setPaused(false); setOrder({ scope, tick, ids: items.map(item => item.id) })
    scrollRef.current?.scrollTo({ top: 0, left: 0 })
  }
  return { items: ordered, paused, scrollRef: attachScroll, pause: () => setPaused(true), back,
    onScroll: (event: UIEvent<HTMLDivElement>) => { if (event.currentTarget.scrollTop > 8 || event.currentTarget.scrollLeft > 8) setPaused(true) } }
}
