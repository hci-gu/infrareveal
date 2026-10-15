import type { DemoStatus } from '@infrareveal/session-state'

export function demoHealthMessage(status: DemoStatus, now: number) {
  if (!status.observing) return 'Waiting for demo capture'
  if (status.maintenance.lastError) return 'History cleanup needs attention'
  const lastCleanup = Date.parse(status.maintenance.lastSuccess)
  if (!Number.isFinite(lastCleanup) || now - lastCleanup > 60_000) return 'Waiting for history cleanup'
  const lastCapture = status.capture?.confirmed_ms ?? 0
  if (!status.capture?.running || !Number.isFinite(lastCapture) || now - lastCapture > 60_000) return 'Packet capture unavailable'
  if (status.capture.error) return 'Packet capture needs attention'
  return ''
}
