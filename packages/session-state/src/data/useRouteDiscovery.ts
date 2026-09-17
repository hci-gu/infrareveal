import { useSyncExternalStore } from 'react'
import { getRouteDiscoveryStatus, type RouteDiscoveryStatus } from './pocketbaseClient'

// All inspectors share one poll. Opening 40 connections must not launch 40 loops.
let current: RouteDiscoveryStatus | null = null
const listeners = new Set<() => void>()
let timer: ReturnType<typeof setInterval> | undefined
let controller: AbortController | undefined
let busy = false
async function update() {
  if (busy) return
  busy = true
  controller = new AbortController()
  try {
    const result = await getRouteDiscoveryStatus(controller.signal)
    if (controller.signal.aborted) return
    current = result
    listeners.forEach(listener => listener())
  } catch { /* Old/disconnected gateways have no current discovery status. */ }
  finally { busy = false }
}
function subscribe(listener: () => void) {
  listeners.add(listener)
  if (!timer) { void update(); timer = setInterval(() => { void update() }, 2000) }
  return () => {
    listeners.delete(listener)
    if (!listeners.size) { clearInterval(timer); timer = undefined; controller?.abort() }
  }
}
const empty = () => null
const noop = () => () => {}
export function useRouteDiscovery(enabled: boolean) {
  return useSyncExternalStore(enabled ? subscribe : noop, enabled ? () => current : empty, empty)
}
