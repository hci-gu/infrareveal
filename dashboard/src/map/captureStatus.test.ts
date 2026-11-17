import { expect, it } from 'vitest'
import type { CaptureInterval, SessionManifest } from '@infrareveal/session-state'
import { captureStatus } from './captureStatus'
const manifest = { active: true, capture: { running: true, quality: 'complete', error: '', dropped: 0, confirmed_ms: 10000 } } as SessionManifest
const interval = (dropped: number, start = 0): CaptureInterval => ({ id: `i${start}`, session: 's', capture_epoch: 'e', start_ms: start, end_ms: start + 1000, quality: dropped ? 'partial' : 'complete', dropped, reason: '' })
it('reports backlog without treating confirmed traffic as missing', () => {
  expect(captureStatus(manifest, 11000)).toBe('')
  expect(captureStatus(manifest, 13200)).toContain('3.2 s behind')
})
it('reports loss inside the shown window, after the source recovers too', () => {
  expect(captureStatus(manifest, 11000, [interval(12), interval(0, 1000), interval(3, 2000)])).toContain('15 packet events missed in the shown time range')
  expect(captureStatus({ ...manifest, active: false }, 50000, [interval(12)])).toContain('12 packet events missed')
})
it('ignores lifetime loss that is outside the shown window', () => {
  const rolling = { ...manifest, capture: { ...manifest.capture, dropped: 64644 } }
  expect(captureStatus(rolling, 11000, [interval(0)])).toBe('')
})
