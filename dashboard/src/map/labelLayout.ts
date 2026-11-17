/** Screen-space placement shared by city totals and country cards, so the two
 * label kinds never cover each other or the city columns. Pure: no deck.gl. */

export type ScreenPoint = [number, number]
export type Rect = { left: number; top: number; width: number; height: number }
export type CountryLabelVariant = 'pill' | 'compact' | 'full'

export type CityLabelInput = {
  id: string
  bytes: number
  /** Projected top of the column, where the total label sits. */
  top: ScreenPoint
  /** Projected foot of the column. */
  base: ScreenPoint
  text: string
  /** Ineligible for a label (e.g. filtered out by selection), but still an obstacle. */
  hidden?: boolean
}

export type CountryLabelInput = {
  id: string
  bytes: number
  anchor: ScreenPoint
  /** Projected size of the country's main landmass. */
  footprint: { width: number; height: number }
  name: string
  total: string
  selected?: boolean
  dimmed?: boolean
}

export type Bounds = { left: number; top: number; right: number; bottom: number }

export type PlacedCountryLabel = {
  id: string
  variant: CountryLabelVariant
  rect: Rect
  anchor: ScreenPoint
  /** True when the label was pushed away from its country and needs a leader line. */
  leader: boolean
}

export type LabelLayout = { cities: string[]; countries: PlacedCountryLabel[] }

const FULL = { width: 200, height: 112 }
const COMPACT = { width: 152, height: 64 }
const PILL_HEIGHT = 24
const CITY_LABEL_HEIGHT = 20
const CITY_LABEL_OFFSET = 14
const GAP = 12
const PAD = 4

/** Size the card by how much room the country itself has on screen. */
export function countryLabelVariant(footprint: { width: number; height: number }, selected = false): CountryLabelVariant {
  if (selected) return 'full'
  if (footprint.width >= FULL.width + 20 && footprint.height >= FULL.height) return 'full'
  if (footprint.width >= COMPACT.width && footprint.height >= COMPACT.height) return 'compact'
  return 'pill'
}

export function countryLabelSize(variant: CountryLabelVariant, name: string, total: string) {
  if (variant === 'full') return FULL
  if (variant === 'compact') return COMPACT
  // swatch + gaps + padding, with a generous per-character estimate for 11px UI text.
  return { width: Math.round(Math.min(190, 40 + name.length * 6.6 + total.length * 6.4)), height: PILL_HEIGHT }
}

export function cityLabelRect(city: Pick<CityLabelInput, 'top' | 'text'>): Rect {
  const width = 12 + city.text.length * 7
  return { left: city.top[0] - width / 2, top: city.top[1] - CITY_LABEL_OFFSET - CITY_LABEL_HEIGHT / 2, width, height: CITY_LABEL_HEIGHT }
}

function columnRect(city: CityLabelInput): Rect {
  const top = Math.min(city.top[1], city.base[1]), bottom = Math.max(city.top[1], city.base[1])
  const left = Math.min(city.top[0], city.base[0]) - 12, right = Math.max(city.top[0], city.base[0]) + 12
  return { left, top, width: right - left, height: bottom - top }
}

export function overlaps(a: Rect, b: Rect, pad = PAD) {
  return a.left < b.left + b.width + pad && b.left < a.left + a.width + pad
    && a.top < b.top + b.height + pad && b.top < a.top + a.height + pad
}

function inside(rect: Rect, bounds: Bounds) {
  return rect.left >= bounds.left && rect.top >= bounds.top && rect.left + rect.width <= bounds.right && rect.top + rect.height <= bounds.bottom
}

function contains(rect: Rect, [x, y]: ScreenPoint) {
  return x >= rect.left && x <= rect.left + rect.width && y >= rect.top && y <= rect.top + rect.height
}

/** Centered on the country first, then rings around it, nearest spots first.
 * Outer rings are joined back to the country by a leader line. */
function candidates([x, y]: ScreenPoint, { width, height }: { width: number; height: number }): Rect[] {
  const at = (left: number, top: number) => ({ left, top, width, height })
  return [at(x - width / 2, y - height / 2), ...[GAP, GAP * 4, GAP * 8].flatMap(gap => [
    at(x - width / 2, y - gap - height),
    at(x + gap, y - gap - height),
    at(x - gap - width, y - gap - height),
    at(x + gap * 1.5, y - height / 2),
    at(x - gap * 1.5 - width, y - height / 2),
    at(x - width / 2, y + gap),
    at(x + gap, y + gap),
    at(x - gap - width, y + gap),
  ])]
}

/** Highest-traffic labels claim space first; anything that cannot fit is
 * dropped (it is still reachable through hover and the inspector). */
export function layoutMapLabels({ cities, countries, bounds, cityBounds = bounds, maxLabels = 14 }: {
  cities: CityLabelInput[]
  countries: CountryLabelInput[]
  bounds: Bounds
  /** City totals sit on their column, so they use their own (tighter) clip region. */
  cityBounds?: Bounds
  maxLabels?: number
}): LabelLayout {
  const columns = cities.map(columnRect)
  const pendingCityLabels = new Map(cities.filter(city => !city.hidden).map(city => [city.id, cityLabelRect(city)]))
  const placed: Rect[] = []
  const result: LabelLayout = { cities: [], countries: [] }
  const priority = (item: { bytes: number; selected?: boolean; dimmed?: boolean; hidden?: boolean }) =>
    item.selected ? Infinity : item.dimmed || item.hidden ? item.bytes / 1000 : item.bytes
  const queue = [
    ...cities.map(city => ({ kind: 'city' as const, item: city, rank: priority(city) })),
    ...countries.map(country => ({ kind: 'country' as const, item: country, rank: priority(country) })),
  ].sort((a, b) => b.rank - a.rank)

  for (const entry of queue) {
    const selected = entry.kind === 'country' && entry.item.selected
    if (entry.kind === 'city') pendingCityLabels.delete(entry.item.id)
    if (!selected && result.cities.length + result.countries.length >= maxLabels) continue
    if (entry.kind === 'city') {
      const city = entry.item
      if (city.hidden) continue
      const [x, y] = city.top
      if (x < cityBounds.left || x > cityBounds.right || y < cityBounds.top || y > cityBounds.bottom) continue
      const rect = cityLabelRect(city)
      if (placed.some(other => overlaps(rect, other))) continue
      placed.push(rect)
      result.cities.push(city.id)
      continue
    }
    const country = entry.item
    const [x, y] = country.anchor
    if (x < bounds.left - 50 || x > bounds.right + 50 || y < bounds.top - 50 || y > bounds.bottom + 50) continue
    const variant = countryLabelVariant(country.footprint, country.selected)
    const size = countryLabelSize(variant, country.name, country.total)
    const options = candidates(country.anchor, size).filter(rect => inside(rect, bounds))
    const clear = (rect: Rect) => !placed.some(other => overlaps(rect, other)) && !columns.some(column => overlaps(rect, column, 2))
    // Cities can't move, so prefer spots that leave their (future) totals room too.
    const free = options.find(rect => clear(rect) && ![...pendingCityLabels.values()].some(other => overlaps(rect, other))) ?? options.find(clear)
    // A selected country always keeps its card, even if it has to overlap something.
    const rect = free ?? (selected ? options[0] ?? clampInto(candidates(country.anchor, size)[0], bounds) : undefined)
    if (!rect) continue
    placed.push(rect)
    result.countries.push({ id: country.id, variant, rect, anchor: country.anchor, leader: !contains(rect, country.anchor) })
  }
  return result
}

function clampInto(rect: Rect, bounds: Bounds): Rect {
  return {
    ...rect,
    left: Math.max(bounds.left, Math.min(bounds.right - rect.width, rect.left)),
    top: Math.max(bounds.top, Math.min(bounds.bottom - rect.height, rect.top)),
  }
}

/** Point on the rect edge closest to the anchor, for drawing the leader line. */
export function leaderEnd(rect: Rect, [x, y]: ScreenPoint): ScreenPoint {
  return [Math.max(rect.left, Math.min(rect.left + rect.width, x)), Math.max(rect.top, Math.min(rect.top + rect.height, y))]
}
