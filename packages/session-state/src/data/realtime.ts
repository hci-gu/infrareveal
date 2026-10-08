import { baseUrl, requestSignal } from './pocketbaseHttp'
import { normalizeRouteRecord } from './routeRecords'
import type { Route } from './types'

export type RealtimeEvent<T> = {
  action: string
  record: T
}

type RealtimeCallback<T> = (event: RealtimeEvent<T>) => void

export const pb = {
  collection(name: string) {
    return {
      subscribe<T>(topic: string, callback: RealtimeCallback<T>) {
        return realtime.subscribe(name, topic, callback)
      },
    }
  },
}

class RealtimeClient {
  private clientId = ''
  private connectPromise: Promise<void> | null = null
  private eventSource: EventSource | null = null
  private subscriptions = new Map<
    string,
    Map<RealtimeCallback<unknown>, EventListener>
  >()

  async subscribe<T>(
    collection: string,
    topic: string,
    callback: RealtimeCallback<T>
  ) {
    const subscription = `${collection}/${topic}`
    const listener: EventListener = (event) => {
      const message = event as MessageEvent<string>
      try {
        const decoded = JSON.parse(message.data) as RealtimeEvent<T>
        if (collection === 'routes' && decoded.action !== 'delete') {
          decoded.record = normalizeRouteRecord(decoded.record as Route) as T
        }
        callback(decoded)
      } catch {
        callback({ action: 'error', record: {} as T })
      }
    }

    const listeners = this.subscriptions.get(subscription) ?? new Map()
    listeners.set(callback as RealtimeCallback<unknown>, listener)
    this.subscriptions.set(subscription, listeners)

    try {
      await this.connect()
      this.eventSource?.addEventListener(subscription, listener)
      await this.submitSubscriptions()
    } catch (error) {
      this.eventSource?.removeEventListener(subscription, listener)
      this.removeSubscription(subscription, callback as RealtimeCallback<unknown>)
      if (this.subscriptions.size === 0) this.disconnect()
      throw error
    }

    return async () => {
      this.eventSource?.removeEventListener(subscription, listener)
      this.removeSubscription(subscription, callback as RealtimeCallback<unknown>)
      await this.submitSubscriptions().catch(() => undefined)
      if (this.subscriptions.size === 0) {
        this.disconnect()
      }
    }
  }

  private async connect() {
    if (this.clientId && this.eventSource) {
      return
    }

    this.connectPromise ??= new Promise((resolve, reject) => {
      const source = new EventSource(`${baseUrl}/api/realtime`)
      const timeout = globalThis.setTimeout(() => {
        source.close()
        this.eventSource = null
        this.connectPromise = null
        reject(new Error('Realtime connection timed out.'))
      }, 15000)

      source.onerror = () => {
        globalThis.clearTimeout(timeout)
        source.close()
        this.eventSource = null
        this.clientId = ''
        this.connectPromise = null
        this.notifyError()
        reject(new Error('Realtime connection failed.'))
      }

      source.addEventListener('PB_CONNECT', (event) => {
        globalThis.clearTimeout(timeout)
        const message = event as MessageEvent<string>
        this.clientId = message.lastEventId
        this.eventSource = source
        this.connectPromise = null
        this.attachListeners()
        resolve()
      })
    })

    return this.connectPromise
  }

  private attachListeners() {
    if (!this.eventSource) {
      return
    }
    for (const [subscription, listeners] of this.subscriptions) {
      for (const listener of listeners.values()) {
        this.eventSource.addEventListener(subscription, listener)
      }
    }
  }

  private async submitSubscriptions() {
    if (!this.clientId) {
      return
    }

    const response = await fetch(`${baseUrl}/api/realtime`, {
      signal: requestSignal(),
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({
        clientId: this.clientId,
        subscriptions: Array.from(this.subscriptions.keys()),
      }),
    })
    if (!response.ok) {
      throw new Error(`PocketBase realtime subscription failed: ${response.status} ${response.statusText}`)
    }
  }

  private removeSubscription(subscription: string, callback: RealtimeCallback<unknown>) {
    const current = this.subscriptions.get(subscription)
    current?.delete(callback)
    if (current?.size === 0) this.subscriptions.delete(subscription)
  }

  private notifyError() {
    for (const listeners of this.subscriptions.values()) {
      for (const callback of listeners.keys()) {
        callback({ action: 'error', record: {} })
      }
    }
  }

  private disconnect() {
    this.eventSource?.close()
    this.eventSource = null
    this.clientId = ''
    this.connectPromise = null
  }
}

const realtime = new RealtimeClient()
