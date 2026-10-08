import { afterEach, describe, expect, it, vi } from 'vitest'
import { createStore } from 'zustand/vanilla'
import { coalescedSelector, stableGatewayData } from './displayUpdates'
import { emptyGatewayData } from './sessionData'

afterEach(() => vi.useRealTimers())
describe('bounded display publications', () => {
  it('coalesces a burst into the latest revision and publishes session switches immediately', () => {
    vi.useFakeTimers()
    const store = createStore(() => ({ session: 'a', version: 0, clock: 0 }))
    const view = coalescedSelector(store, s => s.version, s => s.session, 500)
    const notify = vi.fn()
    const stop = view.subscribe(notify)
    for (let version = 1; version <= 100; version++) store.setState({ version })
    expect(notify).not.toHaveBeenCalled()
    vi.advanceTimersByTime(500)
    expect(notify).toHaveBeenCalledTimes(1)
    expect(view.getSnapshot()).toBe(100)
    store.setState({ clock: 1000 }); vi.advanceTimersByTime(500)
    expect(notify).toHaveBeenCalledTimes(1)
    store.setState({ version: 101 }); store.setState({ session: 'b', version: 0 })
    expect(view.getSnapshot()).toBe(0)
    expect(notify).toHaveBeenCalledTimes(2)
    stop(); vi.advanceTimersByTime(1000)
    expect(notify).toHaveBeenCalledTimes(2)
  })
  it('does not rebuild route/DNS arrays when only activity samples change', () => {
    const stabilize = stableGatewayData()
    const first = emptyGatewayData()
    const route = { id: 'route' } as never
    first.routes = [route]
    const a = stabilize(first)
    const b = stabilize({ ...emptyGatewayData(), routes: [route], flowActivityChunks: [{ id: 'capture' } as never] })
    expect(b.routes).toBe(a.routes)
    expect(b.dnsQueries).toBe(a.dnsQueries)
    expect(b.flowActivityChunks).not.toBe(a.flowActivityChunks)
    expect(stabilize({ ...b, routes: [...b.routes] })).toBe(b)
    expect(stabilize({ ...b, routes: [] }).routes).toHaveLength(0)
  })
})
