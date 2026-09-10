import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import type { SessionWindow } from '../../data/types'
import { resetSessionTimeline } from '../store/sessionStore'
import { sessionController } from './sessionController'
import { getSessionWindow } from '../../data/pocketbaseClient'
vi.mock('../../data/pocketbaseClient', () => ({ getSessionWindow: vi.fn(), getCollectionSessionWindow: vi.fn(), getSessions: vi.fn(), getSessionManifest: vi.fn(), createCollectionSessionManifest: vi.fn(), pb: {} }))
const requests: { signal: AbortSignal; resolve: () => void; reject: (e: Error) => void }[] = []
beforeEach(() => {
  vi.stubGlobal('window', { clearTimeout, clearInterval })
  resetSessionTimeline('s', [])
  requests.length = 0
  vi.mocked(getSessionWindow).mockImplementation(options => new Promise<SessionWindow>((resolve, reject) => {
    const result: SessionWindow = { range: { from: new Date(options.fromMs).toISOString(), to: new Date(options.toMs).toISOString() }, lod: options.lod, watermark: 'fixture', nextCursor: null, flows: [], dnsQueries: [], attributions: [], activityEpisodes: [], flowAssociations: [], flowActivityChunks: [], flowActivityWindows: [], flowActivityStatuses: [], destinations: [], routes: [], gateEvents: [] }
    requests.push({ signal: options.signal!, resolve: () => resolve(result), reject })
    options.signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError')))
  }))
})
afterEach(() => { sessionController.dispose(); vi.unstubAllGlobals() })
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
