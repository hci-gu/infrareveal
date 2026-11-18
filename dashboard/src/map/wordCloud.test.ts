import { expect, it } from 'vitest'
import { domainWeights, fontSize, layoutWords, MAX_FONT, MIN_FONT } from './wordCloud'
import type { MapSeries } from './mapTracks'

const series = (site: string, bytes: number) => ({ site, bytes }) as MapSeries
const measure = (text: string, size: number) => text.length * size * 0.56

it('sums bytes per domain and leaves non-domain fallbacks out', () => {
  const { words, total, excluded } = domainWeights([series('facebook.com', 60), series('facebook.com', 40), series('svt.se', 50), series('endpoint:1.2.3.4|tcp|443', 30), series('203.0.113.9', 5), series('asn:AS13335', 7), series('idle.example', 0)])
  expect(words.map(word => [word.domain, word.bytes])).toEqual([['facebook.com', 100], ['svt.se', 50]])
  expect(total).toBe(150)
  expect(excluded).toBe(42)
})

it('scales area with bytes in fixed steps', () => {
  expect(fontSize(100, 100)).toBe(MAX_FONT)
  expect(fontSize(0, 100)).toBeGreaterThanOrEqual(MIN_FONT - 1)
  expect(fontSize(25, 100) % 2).toBe(0)
  expect(fontSize(99, 100)).toBe(fontSize(100, 100))
})

it('places words inside the box without overlap, deterministically', () => {
  const words = domainWeights(Array.from({ length: 30 }, (_, i) => series(`site${i}.example`, Math.round(100_000 / (i + 1) ** 1.6)))).words
  const placed = layoutWords(words, 300, 220, measure)
  expect(placed.length).toBeGreaterThanOrEqual(12)
  expect(placed[0].domain).toBe('site0.example')
  for (const [i, a] of placed.entries()) {
    const h = a.size * 1.1
    expect(a.x - a.width / 2).toBeGreaterThanOrEqual(0)
    expect(a.x + a.width / 2).toBeLessThanOrEqual(300)
    expect(a.y - h / 2).toBeGreaterThanOrEqual(0)
    expect(a.y + h / 2).toBeLessThanOrEqual(220)
    for (const b of placed.slice(i + 1)) {
      const apart = Math.abs(a.x - b.x) >= (a.width + b.width) / 2 || Math.abs(a.y - b.y) >= (a.size * 1.1 + b.size * 1.1) / 2
      expect(apart).toBe(true)
    }
  }
  expect(layoutWords(words, 300, 220, measure)).toEqual(placed)
})
