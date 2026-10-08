import { afterEach, describe, expect, it, vi } from 'vitest'
import fixture from '../../../../testdata/session-timeline-contract-v1.json'
import { readActivityChunkSummaries } from './collectionTransport'
import type { ActivityChunkSummary } from './types'

const epoch = Date.parse(fixture.session.started_at)
const chunk = (patch: Partial<ActivityChunkSummary> = {}): ActivityChunkSummary => ({ ...fixture.window.flowActivityChunks[0], ...patch })
afterEach(() => vi.unstubAllGlobals())

describe('shared activity summary transport', () => {
  it('paginates compact summaries and selects late writes using storage revision', async () => {
    const first = Array.from({ length: 500 }, (_, i) => chunk({ id: `a${String(i).padStart(3, '0')}` }))
    const fetcher = vi.fn().mockResolvedValueOnce(Response.json({ items: first }))
      .mockResolvedValueOnce(Response.json({ items: [chunk({ id: 'b' }), chunk({ id: 'wrong-session', session: 'other' })] }))
    vi.stubGlobal('fetch', fetcher)
    const result = await readActivityChunkSummaries(fixture.session.id, epoch + 100_000, new AbortController().signal)
    expect(result).toHaveLength(501)
    const params = new URL(fetcher.mock.calls[1][0]).searchParams
    expect(params.get('fields')).not.toContain('samples')
    expect(params.get('filter')).toContain('id > "a499"')
    expect(params.get('filter')).toContain('updated >= "2026-09-10 12:01:10.000Z"')
  })

  it('requests retained summaries including a chunk crossing the boundary', async () => {
    const fetcher = vi.fn().mockResolvedValue(Response.json({ items: [chunk(), chunk({ id: 'new', chunk_start: new Date(epoch + 5000).toISOString() })] }))
    vi.stubGlobal('fetch', fetcher)
    const result = await readActivityChunkSummaries(fixture.session.id, 0, new AbortController().signal, epoch + 6000)
    expect(result.map(record => record.id)).toEqual(['new'])
    expect(new URL(fetcher.mock.calls[0][0]).searchParams.get('filter')).toContain('chunk_start >=')
  })

  it('rejects failed pages rather than returning incomplete totals', async () => {
    const first = Array.from({ length: 500 }, (_, i) => chunk({ id: `a${String(i).padStart(3, '0')}` }))
    vi.stubGlobal('fetch', vi.fn().mockResolvedValueOnce(Response.json({ items: first }))
      .mockResolvedValueOnce(Response.json({ message: 'Unavailable' }, { status: 503 })))
    await expect(readActivityChunkSummaries(fixture.session.id, 0, new AbortController().signal)).rejects.toThrow('Unavailable')
  })

  it('rejects a stalled cursor instead of looping over the same records', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ items: Array.from({ length: 500 }, () => chunk()) })))
    await expect(readActivityChunkSummaries(fixture.session.id, 0, new AbortController().signal)).rejects.toThrow('pagination did not advance')
    expect(fetch).toHaveBeenCalledTimes(2)
  })

  it('does not issue requests for an abandoned map read', async () => {
    const fetcher = vi.fn()
    vi.stubGlobal('fetch', fetcher)
    const controller = new AbortController()
    controller.abort(new Error('Map disposed'))
    await expect(readActivityChunkSummaries(fixture.session.id, 0, controller.signal)).rejects.toThrow('Map disposed')
    expect(fetcher).not.toHaveBeenCalled()
  })
})
