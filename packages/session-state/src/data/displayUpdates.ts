import type { StoreApi } from 'zustand/vanilla'
import type { GatewayData } from './types'

/** Bound display notifications; the store still accepts every event immediately. */
export function coalescedSelector<S, T>(store: Pick<StoreApi<S>, 'getState' | 'subscribe'>, select: (state: S) => T, identity: (state: S) => unknown, intervalMs: number) {
  let snapshot = select(store.getState())
  return {
    getSnapshot: () => snapshot,
    subscribe: (notify: () => void) => {
      let key = identity(store.getState())
      let timer: ReturnType<typeof setTimeout> | undefined
      const publish = () => {
        timer = undefined
        const next = select(store.getState())
        if (next !== snapshot) { snapshot = next; notify() }
      }
      // Changes between render and subscription must not get lost.
      publish()
      const stop = store.subscribe(state => {
        const nextKey = identity(state)
        if (nextKey !== key || intervalMs <= 0) {
          key = nextKey; clearTimeout(timer); publish()
        } else if (!timer && select(state) !== snapshot) timer = setTimeout(publish, intervalMs)
      })
      return () => { stop(); clearTimeout(timer) }
    },
  }
}

/** Store records are immutable. Preserve arrays for collections that did not change. */
export function stableGatewayData() {
  let previous: GatewayData | undefined
  return (data: GatewayData) => {
    if (previous) {
      for (const key of Object.keys(data) as (keyof GatewayData)[]) {
        const next = data[key], before = previous[key]
        if (Array.isArray(next) && Array.isArray(before) && next.length === before.length && next.every((item, i) => item === before[i])) {
          Object.assign(data, { [key]: before })
        }
      }
      if ((Object.keys(data) as (keyof GatewayData)[]).every(key => data[key] === previous![key])) return previous
    }
    previous = data
    return data
  }
}
