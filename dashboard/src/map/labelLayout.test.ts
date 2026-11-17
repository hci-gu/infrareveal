import { describe, expect, it } from 'vitest'
import { cityLabelRect, countryLabelVariant, layoutMapLabels, overlaps } from './labelLayout'
import type { CityLabelInput, CountryLabelInput } from './labelLayout'

const bounds = { left: 12, top: 75, right: 1300, bottom: 700 }
const country = (overrides: Partial<CountryLabelInput> = {}): CountryLabelInput => ({
  id: 'country:SE', bytes: 440_000, anchor: [900, 300], footprint: { width: 40, height: 90 }, name: 'Sweden', total: '440.0 kB', ...overrides,
})
const city = (overrides: Partial<CityLabelInput> = {}): CityLabelInput => ({
  id: 'city:dublin', bytes: 100_000, top: [860, 280], base: [860, 330], text: '100.0 kB', ...overrides,
})

describe('countryLabelVariant', () => {
  it('scales the card with the country size on screen', () => {
    expect(countryLabelVariant({ width: 40, height: 90 })).toBe('pill')
    expect(countryLabelVariant({ width: 160, height: 80 })).toBe('compact')
    expect(countryLabelVariant({ width: 400, height: 220 })).toBe('full')
  })

  it('always expands the selected country', () => {
    expect(countryLabelVariant({ width: 10, height: 10 }, true)).toBe('full')
  })
})

describe('layoutMapLabels', () => {
  it('shows a small country at world zoom as a pill, not a card', () => {
    const { countries } = layoutMapLabels({ cities: [], countries: [country()], bounds })
    expect(countries).toHaveLength(1)
    expect(countries[0].variant).toBe('pill')
    expect(countries[0].rect.height).toBeLessThanOrEqual(24)
  })

  it('keeps country labels off city columns and city totals', () => {
    const cities = [city(), city({ id: 'city:london', top: [960, 270], base: [960, 320], bytes: 50_000 })]
    const layout = layoutMapLabels({ cities, countries: [country()], bounds })
    expect(layout.cities).toEqual(['city:dublin', 'city:london'])
    const [placed] = layout.countries
    expect(placed).toBeDefined()
    for (const item of cities) {
      expect(overlaps(placed.rect, cityLabelRect(item), 0)).toBe(false)
      const column = { left: item.top[0] - 12, top: item.top[1], width: 24, height: item.base[1] - item.top[1] }
      expect(overlaps(placed.rect, column, 0)).toBe(false)
    }
    expect(placed.leader).toBe(!(placed.rect.left <= 900 && placed.rect.left + placed.rect.width >= 900 && placed.rect.top <= 300 && placed.rect.top + placed.rect.height >= 300))
  })

  it('never overlaps labels with each other', () => {
    const countries = Array.from({ length: 8 }, (_, index) => country({ id: `c${index}`, bytes: 1000 * (index + 1), anchor: [700 + index * 15, 300 + index * 10] }))
    const cities = Array.from({ length: 6 }, (_, index) => city({ id: `city${index}`, bytes: 500 * (index + 1), top: [690 + index * 30, 260], base: [690 + index * 30, 300] }))
    const layout = layoutMapLabels({ cities, countries, bounds })
    const rects = [
      ...layout.countries.map(label => label.rect),
      ...cities.filter(item => layout.cities.includes(item.id)).map(cityLabelRect),
    ]
    for (let a = 0; a < rects.length; a += 1) for (let b = a + 1; b < rects.length; b += 1) expect(overlaps(rects[a], rects[b], 0)).toBe(false)
  })

  it('drops the least-trafficked labels first when space runs out', () => {
    const countries = [
      country({ id: 'big', bytes: 10_000_000 }),
      ...Array.from({ length: 20 }, (_, index) => country({ id: `small${index}`, bytes: index, anchor: [900, 300] })),
    ]
    const layout = layoutMapLabels({ cities: [], countries, bounds, maxLabels: 3 })
    expect(layout.countries.map(label => label.id)).toContain('big')
    expect(layout.countries.length).toBeLessThanOrEqual(3)
  })

  it('keeps a selected country even when it has nowhere free to go', () => {
    const crowd = Array.from({ length: 40 }, (_, index) => city({ id: `city${index}`, bytes: 1e9, top: [600 + (index % 10) * 40, 100 + Math.floor(index / 10) * 150], base: [600 + (index % 10) * 40, 240 + Math.floor(index / 10) * 150] }))
    const layout = layoutMapLabels({ cities: crowd, countries: [country({ selected: true })], bounds, maxLabels: 50 })
    expect(layout.countries).toHaveLength(1)
    expect(layout.countries[0].variant).toBe('full')
  })

  it('does not label hidden cities but still avoids their columns', () => {
    const hidden = city({ hidden: true, top: [900, 260], base: [900, 340] })
    const layout = layoutMapLabels({ cities: [hidden], countries: [country()], bounds })
    expect(layout.cities).toEqual([])
    expect(overlaps(layout.countries[0].rect, { left: 888, top: 260, width: 24, height: 80 }, 0)).toBe(false)
  })
})
