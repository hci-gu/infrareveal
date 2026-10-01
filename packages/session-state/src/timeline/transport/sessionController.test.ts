import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SessionWindow } from '../../data/types'
import { resetSessionTimeline, sessionTimelineStore } from '../store/sessionStore'
import { sessionController } from './sessionController'
import { getSessions, getSessionManifest, getSessionWindow, pb } from '../../data/pocketbaseClient'
vi.mock('../../data/pocketbaseClient', () => ({ getSessionWindow: vi.fn(), getCollectionSessionWindow: vi.fn(), getSessions: vi.fn(), getSessionManifest: vi.fn(), createCollectionSessionManifest: vi.fn(), pb: { collection: vi.fn() } }))
const requests: { signal: AbortSignal; resolve: () => void; reject: (e: Error) => void }[] = []
beforeEach(() => {
  vi.stubGlobal('window', { clearTimeout, clearInterval })
  resetSessionTimeline('s', [])
  requests.length = 0
  vi.mocked(pb.collection).mockReset()
  vi.mocked(getSessionWindow).mockImplementation(options => new Promise<SessionWindow>((resolve, reject) => {
    const result: SessionWindow = { range: { from: new Date(options.fromMs).toISOString(), to: new Date(options.toMs).toISOString() }, lod: options.lod, watermark: 'fixture', nextCursor: null, flows: [], dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [], flowActivityChunks: [], flowActivityWindows: [], flowActivityStatuses: [], destinations: [], routes: [], gateEvents: [] }
    requests.push({ signal: options.signal!, resolve: () => resolve(result), reject })
    options.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  }))
})
afterEach(() => { sessionController.dispose(); vi.useRealTimers(); vi.unstubAllGlobals() })
describe('detail request owners', () => {
  it('lets the visible window and a pinned inspector load independently', async () => {
    const visible = sessionController.ensureDetailRange(0, 1000, ['visible'], '50ms', 'tracks')
    const pinned = sessionController.ensureDetailRange(120000, 121000, ['selected'], '50ms', 'inspector')
    expect(requests).toHaveLength(2)
    expect(requests.every(r => !r.signal.aborted)).toBe(true)
    requests.forEach(r => r.resolve()); await Promise.all([visible, pinned])
  })
  it('cancels obsolete seeks only for their owner, and releases requests on teardown', async () => {
    const first = sessionController.ensureDetailRange(0, 1000, ['visible'], '50ms', 'tracks').catch(e => e)
    const pinned = sessionController.ensureDetailRange(120000, 121000, ['selected'], '50ms', 'inspector').catch(e => e)
    const next = sessionController.ensureDetailRange(240000, 241000, ['visible'], '50ms', 'tracks')
    expect(requests[0].signal.aborted).toBe(true)
    expect(requests[1].signal.aborted).toBe(false)
    sessionController.releaseDetailRange('inspector')
    expect(requests[1].signal.aborted).toBe(true)
    expect(requests[2].signal.aborted).toBe(false)
    requests[2].resolve(); await Promise.all([first,pinned,next])
  })
  it('retains a shared in-flight page while either consumer needs it', async () => {
    const a=sessionController.ensureDetailRange(0,1000,['flow'],'50ms','a')
    const b=sessionController.ensureDetailRange(0,1000,['flow'],'50ms','b')
    expect(requests).toHaveLength(1)
    sessionController.releaseDetailRange('a'); expect(requests[0].signal.aborted).toBe(false)
    requests[0].resolve(); await Promise.all([a,b])
  })
})


describe('unattended bootstrap recovery', () => {
  it('uses infrequent repair snapshots while realtime is healthy and fast polling after failure', async () => {
    vi.useFakeTimers()
    vi.stubGlobal('window', { setTimeout, clearTimeout, setInterval, clearInterval })
    vi.stubGlobal('navigator', { onLine: true })
    let disconnect!: () => void
    vi.mocked(pb.collection).mockReturnValue({ subscribe: async (_topic, callback) => {
      disconnect = () => callback({ action: 'error', record: {} as never })
      return async () => {}
    } })
    vi.mocked(getSessions).mockResolvedValue([{ id: 's', name: 'Demo', active: true, started_at: '2026-09-24T12:00:00Z', created: '', updated: '' }])
    vi.mocked(getSessionManifest).mockResolvedValue({ sessionId: 's', name: 'Demo', active: true, startedAt: '2026-09-24T12:00:00Z', endedAt: null, serverNow: '2026-09-24T12:01:00Z', watermark: '', counts: {}, coverage: { from: '2026-09-24T12:00:00Z', to: '2026-09-24T12:01:00Z' } })
    const started = sessionController.start('s')
    await vi.advanceTimersByTimeAsync(0)
    requests[0].resolve()
    await started
    expect(sessionTimelineStore.getState().connectionState).toBe('live')
    await vi.advanceTimersByTimeAsync(8000)
    expect(requests).toHaveLength(1)
    await vi.advanceTimersByTimeAsync(2000)
    expect(requests).toHaveLength(2)
    requests[1].resolve()
    await vi.advanceTimersByTimeAsync(1)
    disconnect()
    await vi.advanceTimersByTimeAsync(2000)
    expect(requests).toHaveLength(3)
    requests[2].resolve()
    await vi.advanceTimersByTimeAsync(1)
  })

  it.each(['offline', 'empty'])('retries after an initially %s gateway', async (failure) => {
    vi.useFakeTimers()
    vi.stubGlobal('window', { setTimeout, clearTimeout, setInterval, clearInterval })
    resetSessionTimeline(null, [])
    const sessions = vi.mocked(getSessions)
    if (failure === 'offline') sessions.mockRejectedValueOnce(new Error('Offline'))
    else sessions.mockResolvedValueOnce([])
    sessions.mockResolvedValue([{ id: 's', name: 'Demo', active: true, ephemeral: true, started_at: '2026-09-24T12:00:00Z', created: '', updated: '' }])
    vi.mocked(getSessionManifest).mockResolvedValue({ sessionId: 's', name: 'Demo', active: true, ephemeral: true, retentionMinutes: 30, startedAt: '2026-09-24T12:00:00Z', endedAt: null, serverNow: '2026-09-24T12:01:00Z', watermark: '', counts: {}, coverage: {from: '2026-09-24T12:00:00Z', to: '2026-09-24T12:01:00Z'} })
    await sessionController.start('s')
    expect(sessionTimelineStore.getState().selectedSessionId).toBeNull()
    await vi.advanceTimersByTimeAsync(2_000)
    expect(sessionTimelineStore.getState().selectedSessionId).toBe('s')
    expect(requests).toHaveLength(1)
    requests[0].resolve()
    await vi.advanceTimersByTimeAsync(1)
    expect(sessionTimelineStore.getState().connectionState).toBe('polling')
  })
})
