import { useEffect, useRef, useState } from 'react'
import { getSessionManifest, type SessionManifest } from '@infrareveal/session-state'

export type SummaryEntry = { manifest?: SessionManifest; receivedAt?: number; error?: string }
const CACHE_LIMIT = 128
export function useSessionSummaries(sessionIds: string[], refresh: number) {
  const [entries, setEntries] = useState<Record<string, SummaryEntry>>({})
  const cache = useRef(new Map<string, SummaryEntry>())
  const key = [...new Set(sessionIds)].join(',')
  useEffect(() => {
    const controller = new AbortController()
    const ids = key.split(',').filter(Boolean)
    const publish = () => { if (!controller.signal.aborted) setEntries(Object.fromEntries(cache.current)) }
    async function load() {
      publish()
      const queue = ids.filter(id => {
        const entry = cache.current.get(id)
        return !entry?.manifest || (entry.manifest.active && Date.now() - (entry.receivedAt ?? 0) >= 4_500)
      })
      await Promise.all(Array.from({ length: Math.min(3, queue.length) }, async () => {
        while (queue.length && !controller.signal.aborted) {
          const id = queue.shift()!
          try {
            const manifest = await getSessionManifest(id, controller.signal)
            if (controller.signal.aborted) return
            cache.current.delete(id)
            cache.current.set(id, { manifest, receivedAt: Date.now() })
          } catch (error) {
            if (controller.signal.aborted) return
            cache.current.set(id, { ...cache.current.get(id), error: error instanceof Error ? error.message : 'Summary unavailable' })
          }
          while (cache.current.size > CACHE_LIMIT) cache.current.delete(cache.current.keys().next().value!)
          publish()
        }
      }))
    }
    void Promise.resolve().then(load)
    return () => controller.abort()
  }, [key, refresh])
  return entries
}
