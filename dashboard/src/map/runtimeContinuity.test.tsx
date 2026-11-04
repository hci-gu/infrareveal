// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { sessionTimelineStore, useActivityBlocks, useMapWindow } from '@infrareveal/session-state'
import type { BlockPage, MapWindow, SessionManifest } from '@infrareveal/session-state'
import * as client from '../../../packages/session-state/src/data/client'
import fixture from '../../../testdata/aggregate-window-v2.json'

vi.mock('../../../packages/session-state/src/data/client', async importOriginal => ({
  ...await importOriginal<typeof client>(), getMapWindow: vi.fn(), getBlocks: vi.fn(),
}))
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
const start = fixture.manifest.started_ms
let id = 0
let root: ReturnType<typeof createRoot>
let container: HTMLDivElement
function deferred<T>() {
  let resolve!: (value: T) => void, reject!: (reason: Error) => void
  const promise = new Promise<T>((yes, no) => { resolve = yes; reject = no })
  return { promise, resolve, reject }
}
beforeEach(() => {
  vi.useFakeTimers()
  vi.resetAllMocks()
  container = document.createElement('div'); document.body.append(container); root = createRoot(container)
  const manifest = { ...fixture.manifest, id: `continuity-${++id}`, active: true, revision: 1 } as SessionManifest
  sessionTimelineStore.setState({ selectedSessionId: manifest.id, manifest, mode: 'live', playback: 'following' })
})
afterEach(async () => { await act(() => root.unmount()); container.remove(); vi.useRealTimers() })
function windowResult(from = start, to = start + 30_000): MapWindow {
  return { ...fixture.window, session_id: sessionTimelineStore.getState().selectedSessionId!, revision: 1, from_ms: from, to_ms: to } as MapWindow
}
async function mapHarness() {
  let result!: ReturnType<typeof useMapWindow>
  function Probe({ from, to, session }: { from: number; to: number; session: string }) {
    result = useMapWindow(session, from, to)
    return <span>{result.window.series.length ? 'Traffic visible' : result.loading ? 'Loading' : 'Empty'}</span>
  }
  const render = async (from = start, to = start + 30_000, session = sessionTimelineStore.getState().selectedSessionId!) => {
    await act(() => root.render(<Probe from={from} to={to} session={session} />))
  }
  await render()
  return { render, get result() { return result } }
}
describe('live window continuity', () => {
  it('keeps captured data visible through a delayed forward window and failed refresh, then recovers', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult())
    const view = await mapHarness()
    expect(container.textContent).toBe('Traffic visible')
    const pending = deferred<MapWindow>()
    vi.mocked(client.getMapWindow).mockReturnValueOnce(pending.promise)
    await view.render(start, start + 60_000)
    expect(container.textContent).toBe('Traffic visible')
    expect(view.result.window.to_ms).toBe(start + 30_000)
    await act(() => pending.reject(new Error('Connection interrupted')))
    expect(container.textContent).toBe('Traffic visible')
    expect(view.result.error).toBe('Connection interrupted')
    // An outage spanning several clock boundaries must not discard retained history.
    const longer = deferred<MapWindow>()
    vi.mocked(client.getMapWindow).mockReturnValueOnce(longer.promise)
    await view.render(start, start + 120_000)
    expect(container.textContent).toBe('Traffic visible')
    await act(() => longer.reject(new Error('Still offline')))
    vi.mocked(client.getMapWindow).mockResolvedValue(windowResult(start, start + 120_000))
    await act(() => vi.advanceTimersByTimeAsync(2000))
    expect(view.result.window.to_ms).toBe(start + 120_000)
    expect(view.result.error).toBe('')
  })
  it('does not reuse a live snapshot for another session or a paused seek', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult()).mockImplementation(() => new Promise(() => {}))
    const view = await mapHarness()
    await act(() => sessionTimelineStore.setState({ playback: 'paused' }))
    await view.render(start, start + 60_000)
    expect(view.result.window.series).toEqual([])
    await view.render(start, start + 30_000, 'another-session')
    expect(view.result.window.series).toEqual([])
  })
  it('publishes a successful empty response instead of retaining old traffic forever', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult())
    const view = await mapHarness()
    vi.mocked(client.getMapWindow).mockResolvedValueOnce({ ...windowResult(start, start + 60_000), series: [], destinations: [] })
    await view.render(start, start + 60_000)
    expect(container.textContent).toBe('Empty')
  })
  it('removes expired samples during retention refresh and invalidates snapshots after a capture clear', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult()).mockImplementation(() => new Promise(() => {}))
    const view = await mapHarness()
    await act(() => {
      const manifest = sessionTimelineStore.getState().manifest!
      sessionTimelineStore.setState({ manifest: { ...manifest, retained_from_ms: start + 50, revision: 2 } })
    })
    await view.render(start + 50, start + 30_000)
    expect(view.result.window.from_ms).toBe(start + 50)
    expect(view.result.window.series.length).toBeGreaterThan(0)
    expect(view.result.window.series.every(chunk => chunk.samples.every(sample => chunk.start_ms + sample[0] >= start + 50))).toBe(true)
    await act(() => {
      const manifest = sessionTimelineStore.getState().manifest!
      sessionTimelineStore.setState({ manifest: { ...manifest, capture: { ...manifest.capture, epoch: 'cleared' } } })
    })
    expect(view.result.hasData).toBe(false)
    expect(view.result.window.series).toEqual([])
  })
  it('keeps a cached window available for the next rollover and ignores late superseded requests', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult())
    const view = await mapHarness()
    const old = deferred<MapWindow>()
    vi.mocked(client.getMapWindow).mockReturnValueOnce(old.promise)
    await view.render(start, start + 60_000)
    await view.render(start, start + 30_000)
    const next = deferred<MapWindow>()
    vi.mocked(client.getMapWindow).mockReturnValueOnce(next.promise)
    await view.render(start, start + 60_000)
    expect(container.textContent).toBe('Traffic visible')
    await act(() => old.resolve({ ...windowResult(), series: [] }))
    expect(container.textContent).toBe('Traffic visible')
    await act(() => next.resolve(windowResult(start, start + 60_000)))
    expect(view.result.window.to_ms).toBe(start + 60_000)
  })
  it('coalesces revisions while loading and catches up after publishing a complete response', async () => {
    vi.mocked(client.getMapWindow).mockResolvedValueOnce(windowResult())
    const view = await mapHarness()
    const pending = deferred<MapWindow>()
    vi.mocked(client.getMapWindow).mockReturnValueOnce(pending.promise)
    await act(() => sessionTimelineStore.setState({ manifest: { ...sessionTimelineStore.getState().manifest!, revision: 2 } }))
    await act(() => sessionTimelineStore.setState({ manifest: { ...sessionTimelineStore.getState().manifest!, revision: 3 } }))
    expect(client.getMapWindow).toHaveBeenCalledTimes(2)
    await act(() => pending.resolve({ ...windowResult(), revision: 2 }))
    expect(view.result.window.revision).toBe(2)
    vi.mocked(client.getMapWindow).mockResolvedValueOnce({ ...windowResult(), revision: 3 })
    await act(() => vi.advanceTimersByTimeAsync(250))
    expect(view.result.window.revision).toBe(3)
  })
  it('retains Activity rows while the live range changes and keeps them on failure', async () => {
    const page: BlockPage = { session_id: sessionTimelineStore.getState().selectedSessionId!, revision: 1, items: fixture.window.blocks } as BlockPage
    vi.mocked(client.getBlocks).mockResolvedValueOnce(page)
    let result!: ReturnType<typeof useActivityBlocks>
    function Probe({ to }: { to: number }) { result = useActivityBlocks(page.session_id, start, to); return null }
    await act(() => root.render(<Probe to={start + 30_000} />))
    expect(result.items.length).toBeGreaterThan(0)
    const pending = deferred<BlockPage>()
    vi.mocked(client.getBlocks).mockReturnValueOnce(pending.promise)
    await act(() => root.render(<Probe to={start + 60_000} />))
    expect(result.items).toEqual(page.items)
    await act(() => pending.reject(new Error('Offline')))
    expect(result.items).toEqual(page.items)
  })
})
