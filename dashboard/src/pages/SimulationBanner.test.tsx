// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { MemoryRouter, Route, Routes } from 'react-router-dom'
import { afterEach, expect, it, vi } from 'vitest'
import { getSimulationStatus, stopSimulation } from '@infrareveal/session-state'
import { SimulationBanner } from './SimulationBanner'

vi.mock('@infrareveal/session-state', () => ({ getSimulationStatus: vi.fn(), stopSimulation: vi.fn() }))
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
afterEach(() => { vi.useRealTimers(); vi.resetAllMocks() })

it('continues checking cleanup during frequent manifest updates and returns to sessions only after confirmation', async () => {
  vi.useFakeTimers()
  vi.mocked(getSimulationStatus).mockResolvedValue({ active: true, session_id: 'demo' })
  const container = document.createElement('div')
  const root = createRoot(container)
  const render = (serverMS: number) => act(() => root.render(<MemoryRouter initialEntries={['/demo']}><Routes>
    <Route path="/demo" element={<SimulationBanner session="demo" expiresMS={4000} serverMS={serverMS} />} />
    <Route path="/" element={<p>Sessions</p>} />
  </Routes></MemoryRouter>))
  try {
    await render(1000)
    for (let i = 1; i <= 8; i++) {
      await act(() => vi.advanceTimersByTimeAsync(250))
      await render(1000 + i * 250)
    }
    expect(getSimulationStatus).toHaveBeenCalledTimes(2)
    expect(container.textContent).toContain('Simulated traffic')
    vi.mocked(getSimulationStatus).mockRejectedValueOnce(new Error('offline'))
    await act(() => vi.advanceTimersByTimeAsync(1000))
    expect(container.textContent).toContain('Simulated traffic')
    vi.mocked(getSimulationStatus).mockResolvedValue({ active: false })
    await act(() => vi.advanceTimersByTimeAsync(1000))
    expect(container.textContent).toBe('Sessions')
    expect(stopSimulation).not.toHaveBeenCalled()
  } finally { await act(() => root.unmount()) }
})
