// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import { GeoIPPanel } from './StoragePage'
import { maintenanceRequest } from '../maintenance/client'
import type { GeoIPStatus } from '../maintenance/client'

vi.mock('../maintenance/client', async () => ({ ...await vi.importActual('../maintenance/client'), maintenanceRequest: vi.fn() }))
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
afterEach(() => { vi.useRealTimers(); vi.resetAllMocks() })
const idle = { available: true, database_type: 'GeoLite2-City', configured: true, account_id: '123', phase: 'idle', bytes: 50000 } as GeoIPStatus

it('follows a background update across polling and shows a failed refresh with the installed database intact', async () => {
  vi.useFakeTimers()
  vi.mocked(maintenanceRequest).mockResolvedValueOnce(idle)
  const container = document.createElement('div'), root = createRoot(container)
  try {
    await act(() => root.render(<GeoIPPanel />))
    await act(() => vi.advanceTimersByTimeAsync(1))
    expect(container.textContent).toContain('GeoLite2-City')
    vi.mocked(maintenanceRequest).mockResolvedValueOnce({ ...idle, phase: 'downloading', message: 'Downloading', downloaded_bytes: 4096 })
      .mockResolvedValueOnce({ ...idle, phase: 'validating', message: 'Checking the downloaded database.' })
      .mockResolvedValueOnce({ ...idle, phase: 'failed', error: 'Download incomplete' })
    await act(() => [...container.querySelectorAll('button')].find(b => b.textContent === 'Refresh GeoIP database')!.click())
    expect(maintenanceRequest).toHaveBeenCalledWith('geoip/refresh', 'POST')
    await act(() => vi.advanceTimersByTimeAsync(1))
    expect(container.textContent).toContain('Checking the downloaded database')
    await act(() => vi.advanceTimersByTimeAsync(1500))
    expect(container.textContent).toContain('Download incomplete')
    expect(container.textContent).toContain('GeoLite2-City')
    expect([...container.querySelectorAll('button')].find(b => b.textContent === 'Refresh GeoIP database')?.disabled).toBe(false)
    const calls = vi.mocked(maintenanceRequest).mock.calls.length
    await act(() => vi.advanceTimersByTimeAsync(5000))
    expect(maintenanceRequest).toHaveBeenCalledTimes(calls)
  } finally { await act(() => root.unmount()) }
})
