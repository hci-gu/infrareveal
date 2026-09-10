import { describe, expect, it } from 'vitest'
import type { Destination, Route } from '@infrareveal/session-state'
import { hasMapCoordinates, mapRoutePath, routeProgress } from './mapRoutes'
import { bundleMapArcs } from './bundleMapArcs'
import type { MapArc } from './mapModel'

const origin = { longitude: 11.91737, latitude: 57.69226, label: 'Gateway' }
const destination: Destination = { id: 'destination', ip: '203.0.113.10', reverse_dns: '', asn: 64500, organization: '', provider_label: '', city: 'Ballerup', country: 'Denmark', lat: 55.7123, lon: 12.0564, last_seen: '2026-09-10T10:01:00Z' }
const hop = (ttl: number, address: string, lat = 0, lon = 0) => ({ ttl, address, missing: !address, lat, lon, timings: address ? [3.4, 2.8] : [] })
const route = (hops: Route['hops'], patch: Partial<Route> = {}): Route => ({ id: 'route', session: 'session', destination: destination.id, destination_ip: destination.ip, destination_port: 443, protocol: 'tcp', method: 'tcp:443', hops, complete: true, error: '', completed_at: '2026-09-10T10:00:30Z', ...patch })

describe('traceroute geography', () => {
  it('maps the real gateway response shape without turning private and unanswered hops into 0,0 locations', () => {
    // The gateway returns a private first hop, a located second hop, then timeouts until the destination.
    const path = mapRoutePath(route([hop(1, '192.168.10.1'), hop(2, '198.51.100.1', 57.7065, 11.967), ...Array.from({ length: 7 }, (_, i) => hop(i + 3, '')), hop(10, destination.ip, destination.lat, destination.lon)]), origin, destination)
    expect(path.positions).toEqual([[origin.longitude, origin.latitude], [11.967, 57.7065], [destination.lon, destination.lat]])
    expect(path.gaps).toEqual([true, true])
    expect(path.complete).toBe(true)
    expect(path.nodes[1]).toMatchObject({ kind: 'hop', ttl: 2, address: '198.51.100.1', rttMs: 2.8 })
  })

  it('orders TTLs and keeps consecutive located responses solid', () => {
    const path = mapRoutePath(route([hop(3, destination.ip, 55, 12), hop(1, '198.51.100.1', 56, 11), hop(2, '198.51.100.2', 56, 11)]), origin, destination)
    expect(path.positions).toEqual([[origin.longitude, origin.latitude], [11, 56], [destination.lon, destination.lat]])
    expect(path.gaps).toEqual([false, false])
    expect(path.nodes[path.nodes.length - 1]?.kind).toBe('destination')
  })

  it('marks skipped TTLs and an unreached destination as unknown spans', () => {
    const path = mapRoutePath(route([hop(1, '198.51.100.1', 56, 11), hop(4, '198.51.100.4', 55, 10)], { complete: false }), origin, destination)
    expect(path.gaps).toEqual([false, true, true])
    expect(path.nodes[path.nodes.length - 1]).toMatchObject({ kind: 'destination', rttMs: null })
  })

  it('retains a direct approximate connection when no hop can be located', () => {
    const path = mapRoutePath(route([hop(1, '192.168.10.1'), hop(2, ''), hop(3, '198.51.100.3', NaN, 12), hop(4, destination.ip)], { complete: true }), origin, destination)
    expect(path.positions).toEqual([[origin.longitude, origin.latitude], [destination.lon, destination.lat]])
    expect(path.gaps).toEqual([true])
    expect(path.nodes[path.nodes.length - 1]).toMatchObject({ ttl: 4, address: destination.ip })
    expect(hasMapCoordinates(0, 12)).toBe(true)
    expect(hasMapCoordinates(55, 0)).toBe(true)
    expect(hasMapCoordinates(91, 12)).toBe(false)
  })

  it('does not draw a zero-length extra segment when the last router and destination share a city', () => {
    const path = mapRoutePath(route([hop(1, '198.51.100.1', destination.lat, destination.lon), hop(2, destination.ip, destination.lat, destination.lon)]), origin, destination)
    expect(path.positions).toHaveLength(2)
    expect(path.gaps).toHaveLength(1)
    expect(path.nodes[1]).toMatchObject({ kind: 'destination', ttl: 2, address: destination.ip })
  })

  it('shares distance-based progress across the route including a dateline crossing', () => {
    const progress = routeProgress([[179, 0], [-179, 0], [-173, 0]])
    expect(progress[0]).toBe(0)
    expect(progress[1]).toBeCloseTo(.25)
    expect(progress[2]).toBe(1)
    expect(routeProgress([[12, 57], [12, 57], [12, 57]])).toEqual([0, .5, 1])
  })

  it('keeps different phases and unknown spans separate when bundling shared geography', () => {
    const arc: MapArc = { id: 'a', endpointId: 'a', trackId: 'track', routeId: 'route-a', sourcePosition: [12, 57], targetPosition: [8, 50], activeFlowCount: 1, bytes: 100, tilt: 0, progressStart: 0, progressEnd: .3, gap: false }
    const bundles = bundleMapArcs([arc, { ...arc, id: 'b', endpointId: 'b', routeId: 'route-b' }, { ...arc, id: 'c', endpointId: 'c', progressEnd: .6 }, { ...arc, id: 'd', endpointId: 'd', gap: true }])
    expect(bundles).toHaveLength(3)
    expect(bundles[0].endpointIds).toEqual(['a', 'b'])
    expect(bundles[0].bytes).toBe(200)
  })
})

it('marks both sides of multiple responders as uncertain and keeps alternate paths separate', () => {
  const route: Route = {
    id: 'route', session: 'session', destination: '', destination_ip: '203.0.113.9', destination_port: 443, protocol: 'tcp', method: 'tcp:443', complete: true, error: '', completed_at: '2026-09-10T12:00:00Z',
    hops: [
      {ttl: 1, address: '192.0.2.1', missing: false, timings: [1], lat: 58, lon: 12, state: 'multipath', replies: [{address: '192.0.2.1', probe_id: 1, rtt_ms: 1}, {address: '192.0.2.2', probe_id: 2, rtt_ms: 2}]},
      {ttl: 2, address: '203.0.113.9', missing: false, timings: [3], lat: 59, lon: 13},
    ],
    alternate_routes: [{method: 'icmp-paris', measured_at: '2026-09-10T12:00:00Z', destination_reached: false, responding_hops: 1, located_hops: 1, hops: [{ttl: 1, address: '198.51.100.1', missing: false, timings: [1], lat: 60, lon: 14}]}],
  }
  const destination: Destination = {id: '', ip: route.destination_ip, reverse_dns: '', asn: 0, organization: '', provider_label: '', city: '', country: '', lat: 59, lon: 13, last_seen: ''}
  const path = mapRoutePath(route, {latitude: 57, longitude: 11, label: 'Gateway'}, destination)
  expect(path.positions).toEqual([[11, 57], [12, 58], [13, 59]])
  expect(path.gaps).toEqual([true, true])
  expect(path.nodes.map(node => node.address)).not.toContain('198.51.100.1')
})
