export type DisplayState = {
  phase: 'off' | 'checking' | 'active' | 'reconnecting' | 'ended' | 'stopping'
  expiresAt: number
  error: string
}
type Registration = { token: string; renewAfterMs: number; validForMs: number }
type StorageLike = Pick<Storage, 'getItem' | 'setItem' | 'removeItem'>

/** One owner per tab: no unload request (refresh must retain the grace period). */
export class DisplayModeClient {
  private state: DisplayState
  private token: string
  private listeners = new Set<() => void>()
  private renewal?: ReturnType<typeof setTimeout>
  private expiration?: ReturnType<typeof setTimeout>
  private request?: AbortController
  private generation = 0
  private connected = false
  private key: string

  constructor(private origin: string, private storage: StorageLike, private fetcher: typeof fetch = (...args) => fetch(...args)) {
    this.key = `infrareveal.display-mode:${origin}`
    this.token = this.storage.getItem(this.key) || ''
    this.state = { phase: this.token ? 'checking' : 'off', expiresAt: 0, error: '' }
  }
  snapshot = () => this.state
  subscribe = (listener: () => void) => { this.listeners.add(listener); return () => { this.listeners.delete(listener) } }
  private publish(state: DisplayState) { this.state = state; this.listeners.forEach(listener => listener()) }
  private cancel() {
    this.generation++
    this.request?.abort()
    clearTimeout(this.renewal)
    clearTimeout(this.expiration)
  }
  connect() {
    this.connected = true
    if (this.token) void this.register('renew')
    return () => { this.connected = false; this.cancel() }
  }
  wake = () => {
    if (this.connected && this.token && !this.request) void this.register('renew')
  }
  start = () => this.register('start')

  private async post(action: string, token: string, signal: AbortSignal) {
    const response = await this.fetcher(`${this.origin}/api/infrareveal/display-mode/${action}`, {
      method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ token }),
      signal: AbortSignal.any([signal, AbortSignal.timeout(8_000)]),
    })
    const body = await response.json()
    if (!response.ok) throw Object.assign(new Error(body.message || 'Display mode is unavailable.'), { status: response.status })
    return body as Registration
  }

  private async register(action: 'start' | 'renew'): Promise<boolean> {
    this.cancel()
    const generation = this.generation
    const request = new AbortController()
    this.request = request
    if (action === 'start') this.publish({ phase: 'checking', expiresAt: 0, error: '' })
    else this.armExpiration()
    const requestedAt = Date.now()
    try {
      const role = await this.post(action, this.token, request.signal)
      if (generation !== this.generation || !this.connected) return false
      if (!role.token || !Number.isFinite(role.validForMs) || role.validForMs <= 0 || role.validForMs > 180_000) throw new Error('Invalid display registration.')
      this.token = role.token
      this.storage.setItem(this.key, role.token)
      // Count network/processing time conservatively; a delayed response must
      // not make the UI claim exclusion after the gateway's lease has expired.
      const expiresAt = requestedAt + role.validForMs
      if (expiresAt <= Date.now()) throw new Error('Display registration expired in transit.')
      this.publish({ phase: 'active', expiresAt, error: '' })
      const delay = Math.max(1000, Math.min(role.renewAfterMs || 20_000, role.validForMs / 3))
      this.renewal = setTimeout(() => { void this.register('renew') }, delay)
      this.armExpiration()
      return true
    } catch (error) {
      if (generation !== this.generation || !this.connected) return false
      const status = error && typeof error === 'object' && 'status' in error ? error.status : 0
      const message = error instanceof Error ? error.message : 'Gateway unavailable.'
      if (status === 403 || status === 409) {
        this.token = ''
        this.storage.removeItem(this.key)
        this.publish({ phase: 'ended', expiresAt: 0, error: message })
      } else if (this.token) {
        this.publish({ ...this.state, phase: 'reconnecting', error: 'Reconnecting to the gateway. Display exclusion needs renewal.' })
        this.renewal = setTimeout(() => { void this.register('renew') }, 5000)
        this.armExpiration()
      } else {
        this.publish({ phase: 'off', expiresAt: 0, error: message })
      }
      return false
    } finally {
      if (generation === this.generation) this.request = undefined
    }
  }

  private armExpiration() {
    clearTimeout(this.expiration)
    if (this.state.expiresAt <= Date.now()) {
      this.publish({ ...this.state, expiresAt: 0 })
      return
    }
    this.expiration = setTimeout(() => {
      this.publish({ ...this.state, phase: 'reconnecting', expiresAt: 0, error: 'Display exclusion could not be renewed. The map is paused until the gateway reconnects.' })
    }, this.state.expiresAt - Date.now())
  }

  stop = async (): Promise<boolean> => {
    this.cancel()
    if (!this.token) {
      this.publish({ phase: 'off', expiresAt: 0, error: '' })
      return true
    }
    const generation = this.generation
    const request = new AbortController()
    this.request = request
    this.publish({ ...this.state, phase: 'stopping', error: '' })
    try {
      await this.post('stop', this.token, request.signal)
      if (generation !== this.generation || !this.connected) return false
      this.token = ''
      this.storage.removeItem(this.key)
      this.publish({ phase: 'off', expiresAt: 0, error: '' })
      return true
    } catch {
      if (generation !== this.generation || !this.connected) return false
      this.publish({ ...this.state, phase: 'reconnecting', error: 'Could not stop display mode. Reconnect and try again.' })
      this.renewal = setTimeout(() => { void this.register('renew') }, 5000)
      this.armExpiration()
      return false
    } finally {
      if (generation === this.generation) this.request = undefined
    }
  }
}
