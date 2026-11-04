import { afterEach, expect, it, vi } from 'vitest'
import { DisplayModeClient } from './DisplayModeClient'

const role = { token: 'role-token', validForMs: 180_000, renewAfterMs: 20_000 }
function storage() {
  const values = new Map<string, string>()
  return { getItem: (key: string) => values.get(key) ?? null, setItem: (key: string, value: string) => { values.set(key, value) }, removeItem: (key: string) => { values.delete(key) } }
}
const json = (body: unknown, status = 200) => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
afterEach(() => { vi.useRealTimers() })

it('registers explicitly, renews on refresh, and stops without a stale renewal', async () => {
  vi.useFakeTimers()
  const saved = storage()
  const fetcher = vi.fn<typeof fetch>().mockImplementation(async () => json(role))
  const first = new DisplayModeClient('', saved, fetcher)
  const disconnect = first.connect()
  expect(fetcher).not.toHaveBeenCalled() // Ordinary viewers are participants.
  expect(await first.start()).toBe(true)
  expect(first.snapshot().phase).toBe('active')
  await vi.advanceTimersByTimeAsync(20_000)
  expect(fetcher.mock.calls[1][0]).toContain('/renew')
  disconnect()
  const refreshed = new DisplayModeClient('', saved, fetcher)
  expect(refreshed.snapshot().phase).toBe('checking') // Map cannot mount yet.
  const cleanup = refreshed.connect()
  await vi.advanceTimersByTimeAsync(0)
  expect(refreshed.snapshot().phase).toBe('active')
  expect(await refreshed.stop()).toBe(true)
  const count = fetcher.mock.calls.length
  await vi.advanceTimersByTimeAsync(200_000)
  expect(fetcher).toHaveBeenCalledTimes(count)
  expect(refreshed.snapshot().phase).toBe('off')
  cleanup()
})

it('retains brief outages but stops claiming exclusion after the grace period', async () => {
  vi.useFakeTimers()
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(role)).mockRejectedValue(new Error('offline'))
  const client = new DisplayModeClient('', storage(), fetcher)
  const cleanup = client.connect()
  await client.start()
  await vi.advanceTimersByTimeAsync(21_000)
  expect(client.snapshot().phase).toBe('reconnecting')
  expect(client.snapshot().expiresAt).toBeGreaterThan(Date.now())
  await vi.advanceTimersByTimeAsync(160_000)
  expect(client.snapshot().expiresAt).toBe(0)
  fetcher.mockResolvedValue(json({ message: 'Display mode ended' }, 409))
  await vi.advanceTimersByTimeAsync(5000)
  expect(client.snapshot().phase).toBe('ended')
  const count = fetcher.mock.calls.length
  await vi.advanceTimersByTimeAsync(30_000)
  expect(fetcher).toHaveBeenCalledTimes(count) // Explicit start required after stop/expiry.
  expect(await client.stop()).toBe(true)
  expect(client.snapshot().phase).toBe('off')
  cleanup()
})

it('does not let a late renewal resurrect an explicitly stopped display', async () => {
  vi.useFakeTimers()
  let finishRenewal: (response: Response) => void = () => {}
  const fetcher = vi.fn<typeof fetch>().mockResolvedValueOnce(json(role))
    .mockImplementationOnce(() => new Promise(resolve => { finishRenewal = resolve }))
    .mockResolvedValue(json({ active: false }))
  const client = new DisplayModeClient('', storage(), fetcher)
  const cleanup = client.connect()
  await client.start()
  await vi.advanceTimersByTimeAsync(20_000)
  await client.stop()
  finishRenewal(json(role))
  await vi.advanceTimersByTimeAsync(0)
  expect(client.snapshot().phase).toBe('off')
  cleanup()
})
