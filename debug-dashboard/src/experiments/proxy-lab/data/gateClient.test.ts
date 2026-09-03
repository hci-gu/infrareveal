import { afterEach, describe, expect, it, vi } from 'vitest'
import { GateClient } from './gateClient'

afterEach(() => vi.unstubAllGlobals())

describe('GateClient', () => {
  it('keeps authorization in a header and decodes status', async () => {
    const requests: Array<{ url: string; headers: Headers }> = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({ url: String(input), headers: new Headers(init?.headers) })
      return Response.json({ requestId: 'r1', status: statusFixture() })
    }))
    const client = new GateClient('secret token', 'http://gateway:8090')
    await client.status()
    await client.pause()
    expect(requests[0].headers.get('Authorization')).toBeNull()
    expect(requests[1].headers.get('Authorization')).toBe('Bearer secret token')
    expect(requests.map((request) => request.url).join(' ')).not.toContain('secret token')
  })

  it('surfaces stale conflicts with the request ID', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => Response.json({ requestId: 'r2', error: 'stale decision' }, { status: 409 })))
    await expect(new GateClient('token').decide('decision', 'accept')).rejects.toMatchObject({ status: 409, requestId: 'r2' })
  })

  it('sends exact strict tuples and packet-step commands without leaking the token', async () => {
    const requests: Array<{ url: string; body: string; headers: Headers }> = []
    vi.stubGlobal('fetch', vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      requests.push({ url: String(input), body: String(init?.body), headers: new Headers(init?.headers) })
      return Response.json({ requestId: 'r3', status: { ...statusFixture(), mode: 'strict' } })
    }))
    const client = new GateClient('memory-only-token', 'http://gateway:8090')
    await client.arm({ sessionId: 'session', mode: 'strict', clientIps: ['10.0.0.2'], strict: { protocol: 'tcp', clientIp: '10.0.0.2', clientPort: 50000, remoteIp: '1.1.1.1', remotePort: 443 } })
    await client.acceptNext(3)
    expect(JSON.parse(requests[0].body).strict).toMatchObject({ clientPort: 50000, remotePort: 443 })
    expect(JSON.parse(requests[1].body)).toMatchObject({ count: 3 })
    expect(requests.every((request) => request.headers.get('Authorization') === 'Bearer memory-only-token')).toBe(true)
    expect(requests.map((request) => `${request.url}${request.body}`).join(' ')).not.toContain('memory-only-token')
  })

  it('passes abort signals to reconciliation requests', async () => {
    let signal: AbortSignal | null = null
    vi.stubGlobal('fetch', vi.fn(async (_input: RequestInfo | URL, init?: RequestInit) => {
      signal = init?.signal ?? null
      return await new Promise<Response>((_resolve, reject) => signal?.addEventListener('abort', () => reject(new DOMException('Aborted', 'AbortError'))))
    }))
    const controller = new AbortController()
    const request = new GateClient('', '').status(controller.signal)
    controller.abort()
    await expect(request).rejects.toMatchObject({ name: 'AbortError' })
    expect((signal as AbortSignal | null)?.aborted).toBe(true)
  })
})

function statusFixture() {
  return {
    enabled: true, supported: true, listenerReady: true, rulesReady: true, armed: false,
    state: 'off', mode: null, sessionId: null, clientIps: [], paused: false, failOpen: true,
    pendingFlows: 0, heldPackets: 0, overflowCount: 0, watchdogReleases: 0, verdictErrors: 0,
    auditDrops: 0, oldestWaitMs: 0, parseBypassCount: 0, lastError: null, flowTimeoutMs: 10000,
    establishedTimeoutMs: 500, dnsTimeoutMs: 2000, maxPendingFlows: 128, maxHeldPackets: 768,
    strictAutoAccept: 0,
    kernelSettings: {},
    queue: { queueDepth: 0, kernelDrops: 0, userDrops: 0, parseBypass: 0 },
  }
}
