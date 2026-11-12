// @vitest-environment jsdom
import { act } from 'react'
import { createRoot } from 'react-dom/client'
import { afterEach, expect, it, vi } from 'vitest'
import { updateSession } from '@infrareveal/session-state'
import type { Session } from '@infrareveal/session-state'
import { DeleteSession } from './DeleteSession'

vi.mock('@infrareveal/session-state', () => ({ updateSession: vi.fn() }))
Object.assign(globalThis, { IS_REACT_ACT_ENVIRONMENT: true })
Object.assign(HTMLDialogElement.prototype, {
  showModal(this: HTMLDialogElement) { this.open = true },
  close(this: HTMLDialogElement) { this.open = false },
})
afterEach(() => vi.resetAllMocks())

it('requires confirmation, retains failed deletions and refreshes only after success', async () => {
  const container = document.createElement('div'), root = createRoot(container), done = vi.fn()
  const session = { id: 'session', name: 'A live session', active: true } as Session
  try {
    await act(() => root.render(<DeleteSession session={session} onDeleted={done} />))
    const dialog = container.querySelector('dialog')!
    await act(() => container.querySelector('button')!.click())
    expect(dialog.open).toBe(true)
    expect(dialog.textContent).toContain('new empty live session')
    expect(updateSession).not.toHaveBeenCalled()
    const buttons = [...dialog.querySelectorAll('button')]
    await act(() => buttons[0].click())
    expect(dialog.open).toBe(false)
    expect(updateSession).not.toHaveBeenCalled()
    await act(() => container.querySelector('button')!.click())
    vi.mocked(updateSession).mockRejectedValueOnce(new Error('Storage busy'))
    await act(() => buttons[1].click())
    expect(dialog.open).toBe(true)
    expect(dialog.textContent).toContain('Storage busy')
    expect(done).not.toHaveBeenCalled()
    vi.mocked(updateSession).mockResolvedValueOnce(null)
    await act(() => buttons[1].click())
    expect(updateSession).toHaveBeenLastCalledWith('session', 'DELETE')
    expect(done).toHaveBeenCalledTimes(1)
    expect(dialog.open).toBe(false)
  } finally { await act(() => root.unmount()) }
})
