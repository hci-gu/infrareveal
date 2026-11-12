// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import type { SessionManifest } from '@infrareveal/session-state'
import { useCaptureStatus } from './useCaptureStatus'

Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
afterEach(() => vi.useRealTimers())

it('ages the warning without server updates or playback, recovers, and stops its clock for recordings', async () => {
  vi.useFakeTimers({ toFake: ['setInterval', 'clearInterval', 'performance'] })
  const container = document.createElement('div')
  const root = createRoot(container)
  const manifest = { active: true, capture: { running: true, quality: 'complete', error: '', dropped: 0, confirmed_ms: 10000 } } as SessionManifest
  function Probe({ value = manifest, server = 11000, received = 0 }: { value?: SessionManifest; server?: number; received?: number }) {
    return <p>{useCaptureStatus(value, { serverMs: server, receivedMs: received })}</p>
  }
  try {
    await act(() => root.render(<Probe />))
    expect(container.textContent).toBe('')
    await act(() => vi.advanceTimersByTimeAsync(2500))
    expect(container.textContent).toContain('3.5 s behind')
    const recovered = { ...manifest, capture: { ...manifest.capture, confirmed_ms: 13500 } }
    await act(() => root.render(<Probe value={recovered} server={14000} received={performance.now()} />))
    expect(container.textContent).toBe('')
    await act(() => vi.advanceTimersByTimeAsync(2000))
    expect(container.textContent).toContain('2.5 s behind')
    await act(() => root.render(<Probe value={{ ...recovered, active: false }} />))
    expect(container.textContent).toBe('')
    expect(vi.getTimerCount()).toBe(0)
  } finally { await act(() => root.unmount()) }
  expect(vi.getTimerCount()).toBe(0)
})
