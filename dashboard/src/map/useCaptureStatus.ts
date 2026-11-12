import { useEffect, useState } from 'react'
import type { SessionManifest, SessionTimelineState } from '@infrareveal/session-state'
import { captureStatus } from './captureStatus'

/** A stalled revision stream must not freeze the capture-age warning. This
 * clock is independent of playback, so pausing history still reports live lag. */
export function useCaptureStatus(manifest: SessionManifest | null, clock: SessionTimelineState['clock']) {
  const [now, setNow] = useState(() => performance.now())
  const active = Boolean(manifest?.active)
  useEffect(() => {
    if (!active) return
    const timer = setInterval(() => setNow(performance.now()), 500)
    return () => clearInterval(timer)
  }, [active])
  return captureStatus(manifest, clock.serverMs + Math.max(0, now - clock.receivedMs))
}
