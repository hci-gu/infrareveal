import { describe, expect, it } from 'vitest'
import { countryFitPositions, countryFootprint } from './countryFootprints'

const location = { city: '', country: 'United States', position: [-97.822, 37.751] as [number, number] }

describe('country-level geography', () => {
  it('matches GeoIP names and region codes without turning cities into footprints', () => {
    const us = countryFootprint(location)
    expect(us?.code).toBe('US')
    expect(us?.polygons.length).toBeGreaterThan(0)
    for (const country of ['US', ' United States ', 'United States of America']) expect(countryFootprint({ ...location, country })).toBe(us)
    expect(countryFootprint({ ...location, city: 'New York' })).toBeNull()
    expect(countryFootprint({ ...location, country: ' ' })).toBeNull()
    expect(countryFootprint({ ...location, country: 'The Netherlands' })?.code).toBe('NL')
  })

  it('retains an explicitly country-level label for territories missing from the coarse basemap', () => {
    expect(countryFootprint({ ...location, country: 'Example territory' })).toMatchObject({ code: 'example territory', name: 'Example territory', polygons: [] })
  })

  it('fits the continental US without expanding to Alaska and Hawaii', () => {
    const bounds = countryFitPositions(countryFootprint(location)!)
    expect(Math.min(...bounds.map(point => point[0]))).toBeGreaterThan(-130)
    expect(Math.max(...bounds.map(point => point[0]))).toBeLessThan(-60)
  })
})
