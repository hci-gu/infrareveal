import type { MapSeries } from './mapTracks'

export type DomainWeight = { domain: string; bytes: number; share: number }
export type PlacedWord = DomainWeight & { x: number; y: number; size: number; width: number; tier: 0 | 1 | 2 }
/** The dashboard loads IBM Plex Sans at 400 and 600; the three largest words are 600. */
export type Measure = (text: string, size: number, weight: 400 | 600) => number

const DOMAIN = /^(?=.{3,253}$)[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)*\.[a-z]{2,}$/
export const MAX_WORDS = 40
export const MIN_FONT = 11
export const MAX_FONT = 34
const FONT_STEP = 2
const PADDING = 4
const SPIRAL_GAP = 6

/** Bytes per registered domain. Endpoint, resolver and network-owner fallbacks
 * are not domain names and stay out of the cloud. */
export function domainWeights(series: Iterable<MapSeries>, limit = MAX_WORDS): { words: DomainWeight[]; total: number; excluded: number } {
  const bytes = new Map<string, number>()
  let total = 0, excluded = 0
  for (const item of series) {
    if (item.bytes <= 0) continue
    const domain = item.site.toLowerCase()
    if (!DOMAIN.test(domain)) { excluded += item.bytes; continue }
    bytes.set(domain, (bytes.get(domain) ?? 0) + item.bytes)
    total += item.bytes
  }
  const words = [...bytes].sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0])).slice(0, limit)
    .map(([domain, value]) => ({ domain, bytes: value, share: total ? value / total : 0 }))
  return { words, total, excluded }
}

/** Area follows bytes (size ∝ √bytes), rounded to fixed steps so live updates
 * only re-flow the cloud when a domain visibly changes size. */
export function fontSize(bytes: number, max: number) {
  const raw = MIN_FONT + (MAX_FONT - MIN_FONT) * Math.sqrt(bytes / max)
  return Math.round(raw / FONT_STEP) * FONT_STEP
}

/** Deterministic Archimedean-spiral placement of horizontal words, largest first,
 * centered in the box. Words that cannot fit are left out, never overlapped. */
export function layoutWords(words: DomainWeight[], width: number, height: number, measure: Measure): PlacedWord[] {
  if (!words.length) return []
  const max = words[0].bytes
  const placed: PlacedWord[] = []
  const boxes: { x0: number; y0: number; x1: number; y1: number }[] = []
  const overlaps = (b: typeof boxes[number]) => boxes.some(o => b.x0 < o.x1 && b.x1 > o.x0 && b.y0 < o.y1 && b.y1 > o.y0)
  words.forEach((word, index) => {
    const size = fontSize(word.bytes, max)
    const w = measure(word.domain, size, index < 3 ? 600 : 400)
    const h = size * 1.1
    if (w > width) return
    // The aspect-corrected spiral spreads words into the pane's wide shape.
    // ~6 px between spiral turns and ~2 px along them finds gaps at any radius.
    for (let angle = 0, steps = 0; steps < 20000; steps += 1, angle += Math.min(0.5, 2 / Math.max(4, angle * SPIRAL_GAP / (Math.PI * 2)))) {
      const radius = angle * SPIRAL_GAP / (Math.PI * 2)
      const cx = radius * Math.cos(angle) * (width / height)
      const cy = radius * Math.sin(angle)
      const box = { x0: cx - w / 2 - PADDING / 2, y0: cy - h / 2 - PADDING / 2, x1: cx + w / 2 + PADDING / 2, y1: cy + h / 2 + PADDING / 2 }
      if (box.x0 < -width / 2 || box.x1 > width / 2 || box.y0 < -height / 2 || box.y1 > height / 2) {
        // The aspect-scaled spiral leaves the box for good past its corners (radius √2·h/2).
        if (radius > height * Math.SQRT1_2 + 1) break
        continue
      }
      if (overlaps(box)) continue
      boxes.push(box)
      placed.push({ ...word, x: cx, y: cy, size, width: w, tier: index < 3 ? 0 : size >= 18 ? 1 : 2 })
      break
    }
  })
  return placed.map(word => ({ ...word, x: word.x + width / 2, y: word.y + height / 2 }))
}

let context: CanvasRenderingContext2D | null | undefined
/** Canvas text metrics in the dashboard font; a proportional estimate without canvas. */
export const measureText: Measure = (text, size, weight) => {
  if (context === undefined) {
    try { context = typeof document === 'undefined' ? null : document.createElement('canvas').getContext('2d') } catch { context = null }
  }
  if (!context) return text.length * size * 0.56
  context.font = `${weight} ${size}px "IBM Plex Sans", system-ui, sans-serif`
  return context.measureText(text).width
}
