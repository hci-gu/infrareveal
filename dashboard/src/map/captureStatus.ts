import type { SessionManifest } from '@infrareveal/session-state'

/** Visible health reports source loss independently of map rendering density. */
export function captureStatus(manifest: SessionManifest | null, serverMS: number): string {
  if (!manifest) return ''
  const capture = manifest.capture, messages: string[] = []
  if (capture.error) messages.push(`Capture ${capture.quality}: ${capture.error}`)
  else if (manifest.active && !capture.running) messages.push('Packet capture is unavailable')
  else if (manifest.active && capture.confirmed_ms > 0 && serverMS - capture.confirmed_ms > 2000) messages.push(`Capture is ${((serverMS - capture.confirmed_ms) / 1000).toFixed(1)} s behind live traffic`)
  if (capture.dropped > 0) messages.push(`${capture.dropped.toLocaleString()} packet events missed during this session`)
  return messages.join(' · ')
}
