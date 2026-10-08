import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import fixture from '../../../../testdata/session-timeline-contract-v1.json'
import routeFixture from '../../../../testdata/route-evidence-contract-v1.json'
import { pb } from './realtime'
import { normalizeRouteRecord } from './routeRecords'
import type { Route, Session, SessionWindow } from './types'
import { applyRealtimeBatch, applySessionWindow, resetSessionTimeline, sessionTimelineStore } from '../timeline/store/sessionStore'
import type { QueuedRealtimeEvent } from '../timeline/store/sessionStore'

class TestEventSource extends EventTarget {
  static instances: TestEventSource[] = []
  closed = false
  onerror: (() => void) | null = null
  constructor(readonly url: string) {
    super()
    TestEventSource.instances.push(this)
    queueMicrotask(() => this.dispatchEvent(new MessageEvent('PB_CONNECT', { lastEventId: 'fixture-client' })))
  }
  close() { this.closed = true }
  send(collection: string, record: unknown, action = 'create') {
    this.dispatchEvent(new MessageEvent(`${collection}/*`, { data: JSON.stringify({ action, record }) }))
  }
}

const window = fixture.window as unknown as SessionWindow
const session = fixture.session as Session
const unsubscribers: Array<() => Promise<void>> = []

beforeEach(() => {
  TestEventSource.instances = []
  vi.stubGlobal('EventSource', TestEventSource)
  vi.stubGlobal('fetch', vi.fn(async () => Response.json({})))
  resetSessionTimeline(session.id, [session])
})
afterEach(async () => {
  for (const stop of unsubscribers.splice(0)) await stop()
  vi.unstubAllGlobals()
})

describe('PocketBase realtime collection contract', () => {
  it('delivers every window collection and session field through one connection', async () => {
    const subscriptions = [
      ['sessions', 'sessions', [session]],
      ['flows', 'flows', window.flows], ['dns_queries', 'dnsQueries', window.dnsQueries],
      ['flow_attributions', 'attributions', window.attributions], ['activity_episodes', 'activityEpisodes', window.activityEpisodes],
      ['flow_associations', 'flowAssociations', window.flowAssociations], ['flow_activity_chunks', 'flowActivityChunks', window.flowActivityChunks],
      ['flow_activity_windows', 'flowActivityWindows', window.flowActivityWindows], ['flow_activity_status', 'flowActivityStatuses', window.flowActivityStatuses],
      ['destinations', 'destinations', window.destinations], ['routes', 'routes', window.routes], ['gate_events', 'gateEvents', window.gateEvents],
    ] as const
    const queued: QueuedRealtimeEvent[] = []
    for (const [collection, storeCollection] of subscriptions) {
      unsubscribers.push(await pb.collection(collection).subscribe<{ id: string }>(
        '*', event => queued.push({ collection: storeCollection, ...event }),
      ))
    }
    expect(TestEventSource.instances).toHaveLength(1)
    const source = TestEventSource.instances[0]
    for (const [collection, , records] of subscriptions) source.send(collection, records[0])
    expect(queued).toHaveLength(subscriptions.length)
    applyRealtimeBatch(queued)
    const state = sessionTimelineStore.getState()
    for (const [, storeCollection, records] of subscriptions) {
      const expected = storeCollection === 'routes' ? [normalizeRouteRecord(window.routes[0])] : records
      expect([...state.entities[storeCollection].values()]).toEqual(expected)
    }
    const lastRequest = vi.mocked(fetch).mock.calls[vi.mocked(fetch).mock.calls.length - 1]?.[1]
    expect(JSON.parse(String(lastRequest?.body))).toEqual({
      clientId: 'fixture-client', subscriptions: subscriptions.map(([collection]) => `${collection}/*`),
    })
    for (const stop of unsubscribers.splice(0)) await stop()
    expect(source.closed).toBe(true)
  })

  it('normalizes route updates without erasing loaded evidence or old flat fields', async () => {
    applySessionWindow(window)
    const received: Route[] = []
    unsubscribers.push(await pb.collection('routes').subscribe<Route>('*', event => {
      received.push(event.record)
      applyRealtimeBatch([{ collection: 'routes', ...event }])
    }))
    const source = TestEventSource.instances[0]
    source.send('routes', routeFixture.route, 'update')
    expect(sessionTimelineStore.getState().entities.routes.get(routeFixture.route.id)?.evidence_updates)
      .toEqual(window.routes[0].evidence_updates)
    source.send('routes', routeFixture.legacyRoute)
    expect(received[1]).toEqual(routeFixture.legacyRoute)
    source.send('routes', { ...routeFixture.route, hops: [{ ttl: 1, replies: [{ address: '9.9.9.9', probe_id: 1, rtt_ms: 3 }] }] })
    expect(received[2].hops?.[0]).toMatchObject({ address: '9.9.9.9', timings: [3], missing: false })
    source.send('routes', { id: routeFixture.route.id, session: session.id }, 'delete')
    expect(sessionTimelineStore.getState().entities.routes.has(routeFixture.route.id)).toBe(false)
  })

  it('reports malformed delivery and connection loss so the owner can reconcile', async () => {
    const callback = vi.fn()
    unsubscribers.push(await pb.collection('gate_events').subscribe('*', callback))
    const source = TestEventSource.instances[0]
    source.dispatchEvent(new MessageEvent('gate_events/*', { data: '{invalid' }))
    expect(callback).toHaveBeenLastCalledWith({ action: 'error', record: {} })
    source.onerror?.()
    expect(callback).toHaveBeenCalledTimes(2)
    expect(source.closed).toBe(true)
  })

  it('cleans up a rejected subscription and reconnects for the next owner', async () => {
    vi.mocked(fetch).mockResolvedValueOnce(Response.json({ message: 'Offline' }, { status: 503 }))
    await expect(pb.collection('flows').subscribe('*', () => {})).rejects.toThrow('503')
    expect(TestEventSource.instances[0].closed).toBe(true)
    unsubscribers.push(await pb.collection('routes').subscribe('*', () => {}))
    expect(TestEventSource.instances).toHaveLength(2)
    expect(JSON.parse(String(vi.mocked(fetch).mock.calls[vi.mocked(fetch).mock.calls.length - 1]?.[1]?.body)).subscriptions).toEqual(['routes/*'])
  })
})
