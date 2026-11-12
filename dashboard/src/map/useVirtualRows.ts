import { useCallback, useState } from 'react'
import type { UIEvent } from 'react'

/** Fixed-height rows bound DOM work while all records remain scrollable. */
export function useVirtualRows<T>(items: T[], height: number, scope: string) {
  const [position, setPosition] = useState({ scope, top: 0, viewport: 800 })
  const top = position.scope === scope ? position.top : 0
  const first = Math.max(0, Math.min(Math.floor(top / height) - 4, items.length - 1))
  const count = Math.ceil(position.viewport / height) + 8
  const onScroll = useCallback((event: UIEvent<HTMLDivElement>) => {
    setPosition({ scope, top: event.currentTarget.scrollTop, viewport: event.currentTarget.clientHeight || 800 })
  }, [scope])
  return { rows: items.slice(first, first + count), first, before: first * height,
    after: Math.max(0, items.length - first - count) * height, onScroll }
}
