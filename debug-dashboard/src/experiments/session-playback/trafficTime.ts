export type TimeRange = { fromMs: number; toMs: number }
export function clampTime(time: number, bounds: TimeRange) {
  return Math.max(bounds.fromMs, Math.min(bounds.toMs, Number.isFinite(time) ? time : bounds.fromMs))
}
export function viewportAt(cursor: number, span: number, bounds: TimeRange): TimeRange {
  const width = span > 0 ? Math.min(span, Math.max(1, bounds.toMs - bounds.fromMs)) : Math.max(1, bounds.toMs - bounds.fromMs)
  const fromMs = Math.max(bounds.fromMs, Math.min(bounds.toMs - width, cursor - width * .5))
  return { fromMs, toMs: fromMs + width }
}
export function timeAtPixel(x: number, width: number, range: TimeRange) {
  return clampTime(range.fromMs + x / Math.max(1, width) * (range.toMs - range.fromMs), range)
}
export function pixelAtTime(time: number, width: number, range: TimeRange) {
  return (time - range.fromMs) / Math.max(1, range.toMs - range.fromMs) * width
}
export function rulerStep(span: number, width: number) {
  const desired = span / Math.max(1, width / 85)
  return [1000, 2000, 5000, 10_000, 15_000, 30_000, 60_000, 120_000, 300_000, 600_000, 1800_000, 3600_000, 86400_000].find(step => step >= desired) ?? 86400_000
}
export function inputHasOwnKeys(target: EventTarget | null) {
  return target instanceof Element && Boolean(target.closest('input,textarea,select,button,summary,a,[contenteditable=true],[role=separator]'))
}
