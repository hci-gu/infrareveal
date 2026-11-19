import { describe, expect, it } from 'vitest'
import { angularDistance, destinationPoint, facesCamera, globeOutline, sphericalCentroid } from './globe'
import { mapProjection } from './mapProjection'
import { parseMapPreferences } from './mapPreferences'

describe('globe geometry', () => {
  it('measures angles between positions on the sphere', () => {
    expect(angularDistance([0, 0], [90, 0])).toBeCloseTo(90)
    expect(angularDistance([170, 10], [-170, 10])).toBeLessThan(21)
  })

  it('knows which side of the globe faces the camera', () => {
    const gothenburg: [number, number] = [11.9, 57.7]
    expect(facesCamera(gothenburg, [18.07, 59.33])).toBe(true)
    expect(facesCamera(gothenburg, [-74, 40.7])).toBe(true)
    expect(facesCamera(gothenburg, [151.2, -33.9])).toBe(false)
  })

  it('centres on the spherical, not the planar, mean', () => {
    // Across the antimeridian the planar mean would land near Greenwich.
    const [lon, lat] = sphericalCentroid([[170, 0], [-170, 0]])
    expect(Math.abs(lon)).toBeCloseTo(180)
    expect(lat).toBeCloseTo(0)
  })

  it('is a selectable projection and remembers the spin toggle', () => {
    expect(mapProjection('globe')).toMatchObject({ globe: true, tiles: false, greatCircle: true, wrap: false })
    expect(mapProjection('mercator').globe).toBe(false)
    expect(parseMapPreferences(JSON.stringify({ projection: 'globe', spin: true }))).toMatchObject({ projection: 'globe', spin: true })
    expect(parseMapPreferences(null)).toMatchObject({ spin: false })
  })

  it('travels along great circles and finds the globe rim on screen', () => {
    const [lon, lat] = destinationPoint([0, 0], 90, 90)
    expect(lon).toBeCloseTo(90)
    expect(lat).toBeCloseTo(0)
    // An orthographic stand-in projection: the rim is at 90 degrees, radius 100 px.
    const project = ([x, y]: number[]) => [Math.sin(x * Math.PI / 180) * Math.cos(y * Math.PI / 180) * 100 + 400, -Math.sin(y * Math.PI / 180) * 100 + 300]
    const outline = globeOutline(project, [0, 0])
    expect(outline.center).toEqual([400, 300])
    expect(outline.radius).toBeCloseTo(100)
  })
})
