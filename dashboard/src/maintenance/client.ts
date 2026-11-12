import { baseUrl } from '@infrareveal/session-state'

export type StorageStatus = {
  checked_ms: number
  disk: { total_bytes: number; used_bytes: number; available_bytes: number; read_only: boolean; state: 'ok' | 'low' | 'critical' | 'read_only' | 'unknown' }
  databases: { name: string; bytes: number; wal_bytes: number; reusable_bytes: number }[]
  session_counts: { session: string; chunks: number }[] | null
  maintenance: { lastSuccess: string; lastError: string }
  hardware_health: string
}
export type GeoIPStatus = {
  available: boolean; database_type: string; build_ms: number; bytes: number
  configured: boolean; account_id: string; phase: string; downloaded_bytes: number
  started_ms: number; finished_ms: number; error: string; message: string
}

export async function maintenanceRequest<T>(path: string, method = 'GET', body?: unknown, signal?: AbortSignal): Promise<T> {
  const response = await fetch(`${baseUrl}/api/infrareveal/${path}`, {
    method, headers: body ? { 'Content-Type': 'application/json' } : undefined,
    body: body ? JSON.stringify(body) : undefined,
    signal: signal ? AbortSignal.any([signal, AbortSignal.timeout(20_000)]) : AbortSignal.timeout(20_000),
  })
  const data = await response.json().catch(() => null)
  if (!response.ok) throw new Error(data?.message || data?.error || `Request failed (${response.status})`)
  return data as T
}

export function storageBytes(bytes: number) {
  if (!Number.isFinite(bytes)) return 'Unavailable'
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB']
  let n = Math.max(0, bytes), i = 0
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++ }
  return `${n.toLocaleString('en-GB', { maximumFractionDigits: i ? 1 : 0 })} ${units[i]}`
}
