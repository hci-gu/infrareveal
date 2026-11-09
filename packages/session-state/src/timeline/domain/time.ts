/** Canonical epoch/frame projection used by live and recorded consumers. */
export const FPS = 30

export function frameForTime(epochMs: number, timeMs: number, fps = FPS) {
  return Math.max(0, Math.round(((timeMs - epochMs) / 1000) * fps))
}

export function timeForFrame(epochMs: number, frame: number, fps = FPS) {
  return epochMs + (frame / fps) * 1000
}
