import { describe, expect, it } from 'vitest'
import type { RouteEvidence, RouteHop, TrafficChunk } from '@infrareveal/session-state'
import { buildRouteTree, hopPosition } from './routeTree'
import type { LocationTraffic } from './mapWorkspace'
import type { MapSeries } from './mapTracks'
import type { MapPosition } from './mapModel'

const origin = { latitude: 57.7, longitude: 11.97, label: 'Gothenburg' }
const binding = (ip: string) => ({ session: 's', destination_ip: ip, protocol: 'tcp', destination_port: 443, network_epoch: 'n' })
function series(id: string, ip: string, trackId = id): MapSeries {
  return { id, trackId, label: id, client: 'c', site: id, hostname: id, chunks: [binding(ip) as TrafficChunk], startMs: 0, endMs: 1, lastActivityMs: 1, bytes: 0, mapped: true, location: '', provider: '' }
}
function location(id: string, position: MapPosition, items: MapSeries[]): LocationTraffic {
  return { id, label: id, detail: '', position, received: 0, sent: 0, partial: false, bytes: 0, lastActivityMs: 1, series: items }
}
const hop = (address: string, lat?: number, lon?: number, extra: Partial<RouteHop> = {}): RouteHop => ({ ttl: 1, address, missing: false, timings: [1], lat, lon, ...extra })
function route(ip: string, hops: RouteHop[], reached = true): RouteEvidence {
  return { ...binding(ip), id: `r-${ip}`, kind: 'path', network_context: '', binding_key: '', attempt_id: '', revision: 1, method: 'tcp', status: 'complete', reason: '', fingerprint: '', measured_ms: 0, available_ms: 0, fresh_until_ms: 100, valid_until_ms: 100, destination_reached: reached, hops }
}
const STOCKHOLM: MapPosition = [18.07, 59.33], FRANKFURT: MapPosition = [8.68, 50.11], AMSTERDAM: MapPosition = [4.9, 52.37], LONDON: MapPosition = [-0.12, 51.5]

describe('route tree', () => {
  it('merges shared upstream segments and sums their traffic', () => {
    const locations = [location('ams', AMSTERDAM, [series('a', '1.1.1.1')]), location('lon', LONDON, [series('b', '2.2.2.2')])]
    const routes = [
      route('1.1.1.1', [hop('10.0.0.1'), hop('9.9.9.1', STOCKHOLM[1], STOCKHOLM[0]), hop('9.9.9.2', FRANKFURT[1], FRANKFURT[0])]),
      route('2.2.2.2', [hop('9.9.9.1', STOCKHOLM[1], STOCKHOLM[0]), hop('9.9.9.3', FRANKFURT[1] + .1, FRANKFURT[0]), hop('8.8.8.8', LONDON[1], LONDON[0])]),
    ]
    const volumes = new Map([['a', { received: 100, sent: 10, partial: false }], ['b', { received: 50, sent: 5, partial: false }]])
    const tree = buildRouteTree(locations, routes, origin, volumes, 10)
    const trunk = tree.edges.find(edge => edge.from[0] === origin.longitude)!
    expect(trunk).toMatchObject({ kind: 'route', received: 150, sent: 15, locationIds: ['ams', 'lon'], trackIds: ['a', 'b'] })
    // Stockholm → Frankfurt is shared even though different routers answered in Frankfurt.
    expect(tree.edges.filter(edge => edge.received === 150)).toHaveLength(2)
    expect(tree.nodes.map(node => node.routers).sort()).toEqual([1, 2])
    // London's final hop sits in the destination cell, so the path ends on the destination marker.
    expect(tree.edges.find(edge => edge.locationIds[0] === 'lon' && edge.to === LONDON)).toBeDefined()
    expect(tree).toMatchObject({ peak: 165, measured: 165, total: 165 })
  })

  it('keeps unmeasured and partial routes visibly direct', () => {
    const locations = [location('ams', AMSTERDAM, [series('a', '1.1.1.1')]), location('lon', LONDON, [series('b', '2.2.2.2')])]
    const routes = [route('2.2.2.2', [hop('9.9.9.2', FRANKFURT[1], FRANKFURT[0])], false)]
    const volumes = new Map([['a', { received: 10, sent: 0, partial: false }], ['b', { received: 30, sent: 0, partial: false }]])
    const tree = buildRouteTree(locations, routes, origin, volumes, 10)
    expect(tree.edges.map(edge => [edge.kind, edge.locationIds[0]]).sort()).toEqual([['direct', 'ams'], ['direct', 'lon'], ['route', 'lon']])
    expect(tree.measured).toBe(30)
    expect(tree.total).toBe(40)
  })

  it('cuts loops introduced by geolocation noise and ignores expired evidence', () => {
    const locations = [location('ams', AMSTERDAM, [series('a', '1.1.1.1')])]
    const routes = [route('1.1.1.1', [hop('x', STOCKHOLM[1], STOCKHOLM[0]), hop('y', FRANKFURT[1], FRANKFURT[0]), hop('z', STOCKHOLM[1], STOCKHOLM[0])])]
    const volumes = new Map([['a', { received: 1, sent: 0, partial: false }]])
    expect(buildRouteTree(locations, routes, origin, volumes, 10).edges).toHaveLength(2)
    expect(buildRouteTree(locations, routes, origin, volumes, 500).edges.map(edge => edge.kind)).toEqual(['direct'])
  })

  it('locates hops from interface evidence and skips country-level geography', () => {
    expect(hopPosition(hop('a', undefined, undefined, { interface_evidence: { a: { geo: { lat: 50, lon: 8 } } } }))).toEqual([8, 50])
    expect(hopPosition(hop('a', 50, 8, { accuracy_km: 1000 }))).toBeNull()
    expect(hopPosition(hop('a', 50, 8, { missing: true }))).toBeNull()
  })
})
