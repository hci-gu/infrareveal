import { describe, expect, it, vi } from 'vitest'
import { TrafficSegments } from './segments'
import type { MapWindow, SessionManifest } from './data/types'

const manifest = (patch: Partial<SessionManifest> = {}): SessionManifest => ({ id: 'session', active: true, revision: 1, retained_from_ms: 0, capture: { epoch: 'one', confirmed_ms: 120000 }, policy: { chunk_ms: 5000, correction_ms: 10000 }, ...patch } as SessionManifest)
const window = (from: number, to: number, revision = 1): MapWindow => ({ session_id: 'session', revision, from_ms: from, to_ms: to, resolution_ms: 1000, complete: true, series: [], coverage: [{ id: 'coverage', session: 'session', capture_epoch: 'one', start_ms: from, end_ms: to, quality: 'complete', dropped: 0, reason: '' }], destinations: [], blocks: [], routes: [] })

describe('finalized segments and mutable capture tail', () => {
  it('reuses history, replaces the complete correction tail and merges coverage', async () => {
    const fetcher = vi.fn(async (_id: string, from: number, to: number) => window(from, to))
    const loader = new TrafficSegments(fetcher)
    const first = await loader.load(manifest(), 0, 120000, 1000, new AbortController().signal)
    expect(fetcher.mock.calls.map(c => c.slice(1, 3))).toEqual([[0, 30000], [30000, 60000], [60000, 90000], [90000, 120000]])
    expect(first.coverage).toHaveLength(1)
    expect(first.coverage[0].end_ms).toBe(120000)
    fetcher.mockClear()
    await loader.load(manifest({ revision: 2 }), 0, 120000, 1000, new AbortController().signal)
    expect(fetcher.mock.calls.map(c => c.slice(1, 3))).toEqual([[90000, 120000]])
    expect(loader.stats.hits).toBe(3)
  })
  it('clips retention and invalidates all history after a clear/restart epoch', async () => {
    const fetcher = vi.fn(async (_id: string, from: number, to: number) => window(from, to))
    const loader = new TrafficSegments(fetcher)
    await loader.load(manifest(), 0, 120000, 1000, new AbortController().signal)
    fetcher.mockClear()
    const clipped = await loader.load(manifest({ retained_from_ms: 45000 }), 0, 120000, 1000, new AbortController().signal)
    expect(clipped.from_ms).toBe(45000)
    expect(clipped.coverage[0].start_ms).toBe(45000)
    expect(fetcher.mock.calls.map(c => c.slice(1, 3))).toEqual([[45000, 60000], [90000, 120000]])
    fetcher.mockClear()
    await loader.load(manifest({ capture: { epoch: 'two', confirmed_ms: 120000 } as SessionManifest['capture'] }), 0, 120000, 1000, new AbortController().signal)
    expect(fetcher).toHaveBeenCalledTimes(4)
  })
  it('never publishes aborted/partially loaded windows', async () => {
    const controller = new AbortController()
    const fetcher = vi.fn(async (_id: string, from: number, to: number) => { controller.abort(); return window(from, to) })
    const loader = new TrafficSegments(fetcher)
    await expect(loader.load(manifest(), 0, 120000, 1000, controller.signal)).rejects.toThrow()
    expect(loader.stats.segments).toBe(0)
  })
  it('ignores alias key order but invalidates a changed classification policy', async () => {
    const fetcher = vi.fn(async (_id: string, from: number, to: number) => window(from, to))
    const loader = new TrafficSegments(fetcher), first = manifest()
    first.policy.aliases = { 'one.test': 'one', 'two.test': 'two' }
    await loader.load(first, 0, 120000, 1000, new AbortController().signal)
    fetcher.mockClear()
    await loader.load({ ...first, revision: 2, policy: { ...first.policy, aliases: { 'two.test': 'two', 'one.test': 'one' } } }, 0, 120000, 1000, new AbortController().signal)
    expect(fetcher.mock.calls.map(c => c.slice(1, 3))).toEqual([[90000, 120000]])
    fetcher.mockClear()
    await loader.load({ ...first, revision: 3, policy: { ...first.policy, aliases: { 'one.test': 'changed' } } }, 0, 120000, 1000, new AbortController().signal)
    expect(fetcher).toHaveBeenCalledTimes(4)
  })

})
