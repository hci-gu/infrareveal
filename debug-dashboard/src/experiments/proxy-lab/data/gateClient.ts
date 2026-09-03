import type { GateDecision, GateStatus } from '../types'

export type StrictTuple = {
  protocol: 'tcp' | 'udp'
  clientIp: string
  clientPort: number
  remoteIp: string
  remotePort: number
}

export class GateAPIError extends Error {
  constructor(readonly status: number, message: string, readonly requestId?: string) {
    super(message)
    this.name = 'GateAPIError'
  }
}

export class GateClient {
  private readonly baseUrl: string

  constructor(private readonly token = '', baseUrl = '') {
    this.baseUrl = baseUrl.replace(/\/$/, '')
  }

  async status(signal?: AbortSignal) {
    return (await this.request<{ requestId: string; status: GateStatus }>('/status', { signal, authenticated: false })).status
  }

  async pending(signal?: AbortSignal) {
    return (await this.request<{ requestId: string; decisions: GateDecision[] }>('/pending', { signal })).decisions
  }

  async arm(body: { sessionId: string; mode: 'flow' | 'strict' | 'dns'; clientIps: string[]; strict?: StrictTuple }, signal?: AbortSignal) {
    return (await this.mutate<{ requestId: string; status: GateStatus }>('/arm', body, signal)).status
  }

  async pause(signal?: AbortSignal) { return (await this.mutate<{ status: GateStatus }>('/pause', {}, signal)).status }
  async resume(signal?: AbortSignal) { return (await this.mutate<{ status: GateStatus }>('/resume', {}, signal)).status }
  async drain(signal?: AbortSignal) { return (await this.mutate<{ status: GateStatus }>('/drain', {}, signal)).status }
  async disarm(signal?: AbortSignal) { return (await this.mutate<{ status: GateStatus }>('/disarm', {}, signal)).status }

  async decide(decisionId: string, verdict: 'accept' | 'drop', actor = 'operator', signal?: AbortSignal) {
    return this.mutate<{ requestId: string; result: GateDecision; alreadyTerminal: boolean }>(
      `/decisions/${encodeURIComponent(decisionId)}`, { verdict, actor }, signal,
    )
  }

  async approveAll(count: number, actor = 'operator', signal?: AbortSignal) {
    return this.mutate<{ requestId: string; results: GateDecision[]; status: GateStatus }>(
      '/approve-all', { actor, reason: `approved ${count} queued decisions` }, signal,
    )
  }

  async acceptNext(count: number, actor = 'operator', signal?: AbortSignal) {
    return (await this.mutate<{ requestId: string; status: GateStatus }>(
      '/strict/accept-next', { count, actor }, signal,
    )).status
  }

  private mutate<T>(path: string, body: unknown, signal?: AbortSignal) {
    return this.request<T>(path, { method: 'POST', body: JSON.stringify(body), signal })
  }

  private async request<T>(path: string, options: RequestInit & { authenticated?: boolean } = {}) {
    const headers = new Headers(options.headers)
    headers.set('Accept', 'application/json')
    if (options.method === 'POST') headers.set('Content-Type', 'application/json')
    if (options.authenticated !== false) {
      if (!this.token) throw new GateAPIError(401, 'Enter the lab control token to use traffic controls.')
      headers.set('Authorization', `Bearer ${this.token}`)
    }
    const response = await fetch(`${this.baseUrl}/api/infrareveal/lab-gate${path}`, { ...options, headers })
    const payload = await response.json().catch(() => null) as { error?: string; message?: string; requestId?: string } | null
    if (!response.ok) {
      throw new GateAPIError(response.status, payload?.error || payload?.message || `Lab gate returned HTTP ${response.status}`, payload?.requestId)
    }
    return payload as T
  }
}
