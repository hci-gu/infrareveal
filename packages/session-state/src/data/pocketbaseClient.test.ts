import { afterEach, describe, expect, it, vi } from 'vitest'
import type { Flow, SessionWindow } from './types'
import {
  formatPocketBaseDate,
  getCollectionSessionWindow,
  getSessionManifest,
  getSessionWindow,
  getSessions,
} from './pocketbaseClient'

afterEach(() => vi.unstubAllGlobals())

describe('PocketBase date filters', () => {
  it('uses the PocketBase date literal format accepted by range comparisons', () => {
    expect(formatPocketBaseDate(Date.parse('2026-08-25T13:29:00.000Z')))
      .toBe('2026-08-25 13:29:00.000Z')
  })
})

describe('shared PocketBase timeline transport', () => {
  it('derives a live manifest when the gateway has not deployed timeline routes yet', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      if (url.pathname.endsWith('/manifest')) {
        return Response.json({ message: 'File not found.' }, { status: 404 })
      }
      return Response.json({
        page: 1,
        totalPages: 1,
        items: [{
          id: 'live-session',
          created: '2026-09-02T10:00:00Z',
          updated: '2026-09-02T10:02:00Z',
          name: 'Live session',
          active: true,
        }],
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const before = Date.now()
    const manifest = await getSessionManifest('live-session')
    const after = Date.now()

    expect(manifest).toMatchObject({
      sessionId: 'live-session',
      name: 'Live session',
      startedAt: '2026-09-02T10:00:00Z',
      endedAt: null,
      active: true,
    })
    expect(Date.parse(manifest.serverNow)).toBeGreaterThanOrEqual(before)
    expect(Date.parse(manifest.serverNow)).toBeLessThanOrEqual(after)
  })

  it('loads a bounded overview from legacy collection routes', async () => {
    const requestedURLs: URL[] = []
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      requestedURLs.push(url)
      const pathParts = url.pathname.split('/')
      const collection = pathParts[pathParts.length - 2]
      const items = collection === 'flows'
        ? [{
            id: 'flow-1',
            session: 'live-session',
            destination_ip: '192.0.2.1',
            start: '2026-09-02T10:00:01Z',
            last_seen: '2026-09-02T10:00:05Z',
          }]
        : collection === 'destinations'
          ? [{ id: 'destination-1', ip: '192.0.2.1' }]
          : []
      return Response.json({ page: 1, totalPages: 1, items })
    })
    vi.stubGlobal('fetch', fetchMock)

    const window = await getCollectionSessionWindow({
      sessionId: 'live-session',
      fromMs: Date.parse('2026-09-02T10:00:00Z'),
      toMs: Date.parse('2026-09-02T10:01:00Z'),
      lod: 'overview',
    })

    expect(window.flows.map((flow) => flow.id)).toEqual(['flow-1'])
    expect(window.destinations.map((destination) => destination.id)).toEqual(['destination-1'])
    const flowRequest = requestedURLs.find((url) => url.pathname.includes('/flows/records'))
    expect(flowRequest?.searchParams.get('filter')).toContain('start < "2026-09-02 10:01:00.000Z"')
    expect(flowRequest?.searchParams.get('filter')).toContain('last_seen >= "2026-09-02 10:00:00.000Z"')
    const destinationRequest = requestedURLs.find((url) => url.pathname.includes('/destinations/records'))
    expect(destinationRequest?.searchParams.get('filter')).toContain('ip="192.0.2.1"')
  })

  it('loads every page of a collection larger than 1,000 records', async () => {
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      const page = Number(url.searchParams.get('page'))
      const start = (page - 1) * 500
      const count = page < 3 ? 500 : 1
      return Response.json({
        page,
        totalPages: 3,
        items: Array.from({ length: count }, (_, index) => ({
          id: `session-${start + index}`,
          created: '2026-09-02T10:00:00Z',
          updated: '2026-09-02T10:00:00Z',
          name: 'Session',
          active: false,
        })),
      })
    })
    vi.stubGlobal('fetch', fetchMock)

    const sessions = await getSessions()
    expect(sessions).toHaveLength(1001)
    expect(new Set(sessions.map((session) => session.id)).size).toBe(1001)
    expect(fetchMock).toHaveBeenCalledTimes(3)
  })

  it('follows opaque range cursors and de-duplicates records by id', async () => {
    const firstFlows = Array.from({ length: 1000 }, (_, index) => ({ id: `flow-${index}` })) as Flow[]
    const fetchMock = vi.fn(async (input: string | URL | Request) => {
      const url = new URL(String(input))
      const secondPage = url.searchParams.get('cursor') === 'page-two'
      return Response.json(makeWindow(
        secondPage ? [{ id: 'flow-999' }, { id: 'flow-1000' }] as Flow[] : firstFlows,
        secondPage ? null : 'page-two',
      ))
    })
    vi.stubGlobal('fetch', fetchMock)

    const window = await getSessionWindow({
      sessionId: 'session-1',
      fromMs: 0,
      toMs: 10_000,
      lod: 'overview',
    })
    expect(window.flows).toHaveLength(1001)
    expect(new Set(window.flows.map((flow) => flow.id)).size).toBe(1001)
    expect(window.nextCursor).toBeNull()
    expect(fetchMock).toHaveBeenCalledTimes(2)
  })
})

function makeWindow(flows: Flow[], nextCursor: string | null): SessionWindow {
  return {
    range: { from: '1970-01-01T00:00:00Z', to: '1970-01-01T00:00:10Z' },
    lod: 'overview',
    watermark: 'rev',
    flows,
    dnsQueries: [],
    attributions: [],
    activityEpisodes: [],
    flowAssociations: [],
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: [],
    destinations: [],
    routes: [],
    nextCursor,
  }
}
