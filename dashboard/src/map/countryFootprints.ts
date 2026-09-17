import countries from './data/countries.json'
import type { MapPosition } from './mapModel'

export type CountryFootprint = {
  code: string
  name: string
  /** A label/layout anchor, never an observed endpoint. */
  position: MapPosition
  polygons: MapPosition[][][]
}

const normalize = (name: string) => name.trim().toLocaleLowerCase('en').replace(/^the /, '')
const byName = new Map<string, CountryFootprint>()
const regionNames = new Intl.DisplayNames(['en'], { type: 'region' })
for (const record of countries) {
  const hasCode = /^[A-Z]{2}$/.test(record.code)
  const country = { ...record, code: hasCode ? record.code : normalize(record.name), name: hasCode ? regionNames.of(record.code) || record.name : record.name } as CountryFootprint
  const names = [hasCode ? record.code : '', record.name]
  if (/^[A-Z]{2}$/.test(record.code)) names.push(regionNames.of(record.code) || '')
  for (const name of names) if (name) byName.set(normalize(name), country)
}
for (const [alias, code] of Object.entries({ 'United States of America': 'US', 'Russian Federation': 'RU', 'Republic of Korea': 'KR', 'Czech Republic': 'CZ', 'Türkiye': 'TR', 'UK': 'GB' })) {
  const country = byName.get(normalize(code))
  if (country) byName.set(normalize(alias), country)
}

export function isCountryLocation(location: { city?: string; country?: string }) {
  return !location.city?.trim() && Boolean(location.country?.trim())
}

/** Missing city is country-level evidence, even if the provider supplied a centroid. */
export function countryFootprint(location: { city?: string; country?: string; position: MapPosition }): CountryFootprint | null {
  if (!isCountryLocation(location)) return null
  return byName.get(normalize(location.country!)) ?? {
    code: normalize(location.country!), name: location.country!.trim(), position: location.position, polygons: [],
  }
}

/** Fit the main landmass, not remote islands on the opposite side of the world. */
export function countryFitPositions(country: CountryFootprint): MapPosition[] {
  const rings = country.polygons.map(polygon => polygon[0])
  const area = (ring: MapPosition[]) => Math.abs(ring.reduce((sum, [x,y], i) => {
    const next = ring[(i + 1) % ring.length]
    return sum + x * next[1] - next[0] * y
  }, 0))
  return [...rings].sort((a, b) => area(b) - area(a))[0] ?? [country.position]
}
