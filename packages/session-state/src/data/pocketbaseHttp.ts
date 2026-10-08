const defaultUrl = typeof window === 'undefined'
  ? 'http://127.0.0.1:8090'
  : `${window.location.protocol}//${window.location.hostname}:8090`

export const baseUrl = (import.meta.env.VITE_POCKETBASE_URL ?? defaultUrl).replace(
  /\/$/,
  ''
)

export async function requestJSON<T>(path: string, signal?: AbortSignal) {
  const response = await fetch(`${baseUrl}${path}`, { signal: requestSignal(signal) })
  if (!response.ok) {
    const payload = await response.json().catch(() => null) as { error?: string; message?: string } | null
    throw new PocketBaseRequestError(
      response.status,
      payload?.error || payload?.message || `PocketBase request failed: ${response.status} ${response.statusText}`,
    )
  }
  return response.json() as Promise<T>
}

class PocketBaseRequestError extends Error {
  constructor(readonly status: number, message: string) {
    super(message)
    this.name = 'PocketBaseRequestError'
  }
}

export function isNotFound(error: unknown): error is PocketBaseRequestError {
  return error instanceof PocketBaseRequestError && error.status === 404
}

// Bound failed requests as well as successful data; a hung connection must not
// prevent live reconciliation indefinitely. Owners still cancel on teardown.
export function requestSignal(signal?: AbortSignal) {
  const timeout = AbortSignal.timeout(20_000)
  return signal ? AbortSignal.any([signal, timeout]) : timeout
}

