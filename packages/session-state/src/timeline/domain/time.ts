/** Canonical epoch/frame projection used by live and recorded consumers. */
export const FPS = 30
export const WINDOW_SEGMENT_MS = 10_000

export function parseEpoch(value: string | null | undefined, fallback = 0) {
  if (!value) return fallback
  const parsed = Date.parse(value)
  return Number.isFinite(parsed) ? parsed : fallback
}

export function frameForTime(epochMs: number, timeMs: number, fps = FPS) {
  return Math.max(0, Math.round(((timeMs - epochMs) / 1000) * fps))
}

export function timeForFrame(epochMs: number, frame: number, fps = FPS) {
  return epochMs + (frame / fps) * 1000
}

export function alignWindowStart(timeMs: number, segmentMs = WINDOW_SEGMENT_MS) {
  return Math.floor(timeMs / segmentMs) * segmentMs
}

export function windowSegments(fromMs: number, toMs: number, segmentMs = WINDOW_SEGMENT_MS) {
  const result: Array<{ fromMs: number; toMs: number }> = []
  for (let start = alignWindowStart(fromMs, segmentMs); start < toMs; start += segmentMs) {
    result.push({ fromMs: start, toMs: start + segmentMs })
  }
  return result
}

export function overlaps(startMs: number, endMs: number, fromMs: number, toMs: number) {
  return startMs < toMs && endMs >= fromMs
}
