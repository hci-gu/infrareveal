import { expect, it } from 'vitest'
import type { SessionManifest } from '@infrareveal/session-state'
import { captureStatus } from './captureStatus'
const manifest = { active: true, capture: { running: true, quality: 'complete', error: '', dropped: 0, confirmed_ms: 10000 } } as SessionManifest
it('reports backlog without treating confirmed traffic as missing', () => {
  expect(captureStatus(manifest, 11000)).toBe('')
  expect(captureStatus(manifest, 13200)).toContain('3.2 s behind')
})
it('keeps cumulative loss visible after the source recovers', () => {
  expect(captureStatus({ ...manifest, capture: { ...manifest.capture, dropped: 12 } }, 11000)).toContain('12 packet events missed')
  expect(captureStatus({ ...manifest, active: false }, 50000)).toBe('')
})
