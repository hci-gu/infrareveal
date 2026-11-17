import type { CaptureInterval, SessionManifest } from '@infrareveal/session-state'

/** Visible health reports source loss independently of map rendering density.
 * Loss is counted from the coverage of the loaded window, not the session's
 * lifetime total: a long-running rolling session would otherwise keep showing
 * drops from weeks ago that are no longer on screen. */
export function captureStatus(manifest: SessionManifest | null, serverMS: number, coverage: readonly CaptureInterval[] = []): string {
  if (!manifest) return ''
  const capture = manifest.capture, messages: string[] = []
  if (capture.error) messages.push(`Capture ${capture.quality}: ${capture.error}`)
  else if (manifest.active && !capture.running) messages.push('Packet capture is unavailable')
  else if (manifest.active && capture.confirmed_ms > 0 && serverMS - capture.confirmed_ms > 2000) messages.push(`Capture is ${((serverMS - capture.confirmed_ms) / 1000).toFixed(1)} s behind live traffic`)
  const dropped = coverage.reduce((sum, interval) => sum + Math.max(0, interval.dropped || 0), 0)
  if (dropped > 0) messages.push(`${dropped.toLocaleString()} packet events missed in the shown time range`)
  return messages.join(' · ')
}
