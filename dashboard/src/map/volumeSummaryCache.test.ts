import { afterEach, describe, expect, it, vi } from 'vitest'
import type { VolumeChunk } from './destinationVolumes'
import { VolumeSummaryCache } from './volumeSummaryCache'

const epoch = Date.parse('2026-09-10T10:00:00Z')
const iso = (ms: number) => new Date(epoch + ms).toISOString()
const chunk = (id: string, patch: Partial<VolumeChunk> = {}): VolumeChunk => ({ id, session: 's', flow: id, chunk_start: iso(0), chunk_ms: 5000, wire_bytes_in: 4000, wire_bytes_out: 1000, capture_complete: true, dropped_events: 0, updated_at_source: iso(5000), updated: iso(5000), ...patch })
afterEach(() => vi.unstubAllGlobals())

describe('incremental destination summaries', () => {
  it('uses deltas for rolling sessions and preserves unchanged flow indexes', async () => {
    let items = [chunk('a'), chunk('b')]
    const fetcher = vi.fn(async (url: string) => { expect(url).toContain('flow_activity_chunks'); return { ok: true, json: async () => ({ items }) } })
    vi.stubGlobal('fetch', fetcher)
    const cache = new VolumeSummaryCache('s')
    const signal = new AbortController().signal
    const first = await cache.refresh(signal, epoch, 0)
    items = [chunk('a', { wire_bytes_in: 8000, updated: iso(6000) })]
    const next = await cache.refresh(signal, epoch, 5000)
    expect(new URL(fetcher.mock.calls[1][0] as string).searchParams.get('filter')).toContain('updated >=')
    expect(next.get('a')?.received.slice(-1)[0]).toBe(8000)
    expect(next.get('b')).toBe(first.get('b'))
    expect(await cache.refresh(signal, epoch, 10_000)).toBe(next)
  })

  it('evicts expired records and repairs missed deletions with occasional snapshots', async () => {
    let items = [chunk('a'), chunk('b', { chunk_start: iso(5000), updated_at_source: iso(10_000) })]
    vi.stubGlobal('fetch', vi.fn(async (url: string) => { expect(url).toContain('flow_activity_chunks'); return { ok: true, json: async () => ({ items }) } }))
    const cache = new VolumeSummaryCache('s'), signal = new AbortController().signal
    await cache.refresh(signal, epoch, 0)
    items = []
    expect((await cache.refresh(signal, epoch + 5000, 5000)).has('a')).toBe(false)
    expect(cache.index.has('b')).toBe(true)
    expect((await cache.refresh(signal, epoch + 5000, 60_000)).size).toBe(0)
  })

  it('does not resurrect an SSE deletion from an in-flight snapshot', async () => {
    const cache = new VolumeSummaryCache('s'), signal = new AbortController().signal
    vi.stubGlobal('fetch', vi.fn(async () => ({ ok: true, json: async () => ({ items: [chunk('a')] }) })))
    await cache.refresh(signal, epoch, 0)
    let finish!: (value: unknown) => void
    vi.stubGlobal('fetch', () => new Promise(resolve => { finish = resolve }))
    const pending = cache.refresh(signal, epoch, 60_000)
    cache.delete('a')
    finish({ ok: true, json: async () => ({ items: [chunk('a')] }) })
    expect((await pending).has('a')).toBe(false)
  })
})
