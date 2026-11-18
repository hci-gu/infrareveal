import { describe, expect, it } from 'vitest'
import type { TrafficChunk } from '@infrareveal/session-state'
import { bearingDegrees, fibreFloorMs, latencyBand, latencyPlane, latencyPosition, mergeRoundTrip, placement, summarizeLatency, windowRoundTrip } from './latency'

const gothenburg = { latitude: 57.69226, longitude: 11.91737, label: 'Gateway' }
const chunk = (start_ms: number, rtt_us?: number, rtt_source?: 'tcp' | 'udp') => ({ start_ms, chunk_ms: 5000, rtt_us, rtt_source }) as TrafficChunk

describe('passive round trips', () => {
  it('prefers TCP handshakes, then the lowest value, within the window', () => {
    const chunks = [chunk(0, 9_000, 'udp'), chunk(5000, 31_000, 'tcp'), chunk(10_000, 24_000, 'tcp'), chunk(60_000, 1_000, 'tcp'), chunk(15_000)]
    expect(windowRoundTrip(chunks, 0, 20_000)).toEqual({ ms: 24, source: 'tcp' })
    expect(windowRoundTrip([chunk(0, 9_000, 'udp')], 0, 20_000)).toEqual({ ms: 9, source: 'udp' })
    expect(windowRoundTrip([chunk(0)], 0, 20_000)).toBeUndefined()
    expect(mergeRoundTrip({ ms: 5, source: 'udp' }, { ms: 30, source: 'tcp' })).toEqual({ ms: 30, source: 'tcp' })
  })

  it('knows the physical floor and flags locations physics rules out', () => {
    const newYork: [number, number] = [-74, 40.7]
    const floor = fibreFloorMs(gothenburg, newYork)
    expect(floor).toBeGreaterThan(55)
    expect(floor).toBeLessThan(65)
    // A "New York" address answering in 4 ms was served from nearby.
    expect(placement(4, floor)).toBe('contradicted')
    expect(placement(95, floor)).toBe('consistent')
  })

  it('lays destinations out by bearing and square-root round trip', () => {
    expect(Math.round(bearingDegrees(gothenburg, [gothenburg.longitude, 70]))).toBe(0)
    expect(Math.round(bearingDegrees(gothenburg, [30, 57.7]))).toBeGreaterThan(80)
    const [x, y] = latencyPlane(100, 90)
    expect(y).toBeCloseTo(0)
    expect(x).toBeCloseTo(2 * latencyPlane(25, 90)[0])
    // Rings stay round on the Web Mercator view: equal plane radii in every direction.
    const north = latencyPosition(100, 0), east = latencyPosition(100, 90)
    expect(Math.log(Math.tan(Math.PI / 4 + north[1] * Math.PI / 360)) * 180 / Math.PI).toBeCloseTo(east[0])
    expect(latencyBand(8).id).toBe('local')
    expect(latencyBand(400).id).toBe('intercontinental')
  })

  it('summarises traffic by round-trip band and flags bytes physics places nearby', () => {
    const summary = summarizeLatency([
      { bytes: 100, rttMs: 4, position: [18.07, 59.33] },
      { bytes: 50, rttMs: 3, position: [-74, 40.7] },
      { bytes: 30, rttMs: 98, position: [-74, 40.7] },
      { bytes: 20 },
    ], gothenburg)
    expect(summary.bands).toEqual({ local: 150, regional: 0, continental: 30, intercontinental: 0, unmeasured: 20 })
    expect(summary).toMatchObject({ total: 200, contradicted: 50, locatedMeasured: 180 })
  })
})
