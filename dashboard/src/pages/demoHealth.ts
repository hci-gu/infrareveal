import type { DemoStatus } from '@infrareveal/session-state'

export function demoHealthMessage(status: DemoStatus, now: number) {
  if (!status.observing) return 'Waiting for demo capture'
  if (status.maintenance.lastError) return 'History cleanup needs attention'
  const lastCleanup = Date.parse(status.maintenance.lastSuccess)
  if (!Number.isFinite(lastCleanup) || now - lastCleanup > 60_000) return 'Waiting for history cleanup'
  const lastCapture = Date.parse(status.capture?.reportedAt ?? '')
  if (!status.capture?.running || !Number.isFinite(lastCapture) || now - lastCapture > 60_000) return 'Packet capture unavailable'
  if (status.capture.lastError) return 'Packet capture needs attention'
  return ''
}
