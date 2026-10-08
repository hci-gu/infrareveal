import { afterEach, describe, expect, it, vi } from 'vitest'
import fixture from '../../../../testdata/session-timeline-contract-v1.json'
import routeFixture from '../../../../testdata/route-evidence-contract-v1.json'
import { getSessionManifest, getSessionWindow } from './pocketbaseClient'
import { getCollectionSessionWindow } from './collectionTransport'
import { normalizeRouteRecord } from './routeRecords'
import { emptySessionWindow } from './sessionData'
import type { Session, SessionManifest, SessionWindow } from './types'

const session = fixture.session as Session
const manifest = fixture.manifest as SessionManifest
const window = fixture.window as unknown as SessionWindow
const request = {
  sessionId: session.id, fromMs: Date.parse(window.range.from), toMs: Date.parse(window.range.to), lod: window.lod,
}
const collections: Record<string, unknown[]> = {
  sessions: [session], flows: window.flows, dns_queries: window.dnsQueries,
  flow_attributions: window.attributions, activity_episodes: window.activityEpisodes,
  flow_associations: window.flowAssociations, flow_activity_chunks: window.flowActivityChunks,
  flow_activity_windows: window.flowActivityWindows, flow_activity_status: window.flowActivityStatuses,
  destinations: window.destinations, routes: [routeFixture.route], route_evidence_updates: routeFixture.updates,
  gate_events: window.gateEvents,
}

afterEach(() => { vi.unstubAllGlobals(); vi.useRealTimers() })

describe('shared session wire contract', () => {
  it.each(['timeline', 'collections'] as const)('reads every record and audit field through %s', async transport => {
    vi.useFakeTimers()
    vi.setSystemTime(Date.parse(manifest.serverNow))
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      if (url.pathname.startsWith('/api/infrareveal/')) {
        if (transport === 'collections') return Response.json({ message: 'Older gateway' }, { status: 404 })
        return Response.json(url.pathname.endsWith('/manifest') ? manifest : window)
      }
      const collection = url.pathname.split('/')[3]
      expect(collections).toHaveProperty(collection)
      return Response.json({ page: 1, totalPages: 1, items: collections[collection] })
    })
    vi.stubGlobal('fetch', fetchMock)

    expect(await getSessionManifest(session.id)).toEqual({
      ...manifest, transport, ...(transport === 'collections' ? { counts: {} } : {}),
    })
    expect(await getSessionWindow(request)).toEqual({
      ...window, routes: window.routes.map(route => normalizeRouteRecord(route)),
    })
    if (transport === 'collections') {
      const names = fetchMock.mock.calls.map(([url]) => new URL(String(url)).pathname.split('/')[3])
      expect(names).toContain('route_evidence_updates')
      expect(names).toContain('gate_events')
    }
  })

  it('merges all collections across opaque pages and keeps the latest duplicate', async () => {
    const cursor = 'route-offset:with,opaque/characters'
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      expect(url.searchParams.get('flow')).toBe(window.flows[0].id)
      if (!url.searchParams.has('cursor')) return Response.json({ ...window, nextCursor: cursor })
      expect(url.searchParams.get('cursor')).toBe(cursor)
      return Response.json({
        ...emptySessionWindow(request.fromMs, request.toMs, request.lod),
        watermark: manifest.watermark,
        flows: [{ ...window.flows[0], bytes_in: 999 }],
        gateEvents: [{ ...window.gateEvents[0], id: 'second-gate' }],
      })
    })
    vi.stubGlobal('fetch', fetchMock)
    expect(await getSessionWindow({ ...request, flowIds: [window.flows[0].id] })).toEqual({
      ...window, flows: [{ ...window.flows[0], bytes_in: 999 }],
      routes: window.routes.map(route => normalizeRouteRecord(route)),
      gateEvents: [...window.gateEvents, { ...window.gateEvents[0], id: 'second-gate' }],
    })
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('tolerates absent optional legacy collections while retaining required flows', async () => {
    vi.stubGlobal('fetch', vi.fn(async (input: string | URL | Request) => {
      return String(input).includes('/flows/records')
        ? Response.json({ items: window.flows, totalPages: 1 })
        : Response.json({ message: 'Absent optional collection' }, { status: 404 })
    }))
    const result = await getCollectionSessionWindow(request)
    expect(result.flows).toEqual(window.flows)
    expect(result.routes).toEqual([])
    expect(result.gateEvents).toEqual([])
  })

  it.each([403, 500])('preserves a %s error instead of switching transports', async status => {
    const fetchMock = vi.fn(async () => Response.json({ message: 'Request failed' }, { status }))
    vi.stubGlobal('fetch', fetchMock)
    await expect(getSessionManifest(session.id)).rejects.toThrow('Request failed')
    await expect(getSessionWindow(request)).rejects.toThrow('Request failed')
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })

  it('passes cancellation to requests without treating it as missing timeline support', async () => {
    const controller = new AbortController()
    controller.abort(new Error('Session changed'))
    const fetchMock = vi.fn(async (_input: unknown, init?: RequestInit) => {
      expect(init?.signal?.aborted).toBe(true)
      init?.signal?.throwIfAborted()
      return Response.json(window)
    })
    vi.stubGlobal('fetch', fetchMock)
    await expect(getSessionWindow({ ...request, signal: controller.signal })).rejects.toThrow('Session changed')
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})
