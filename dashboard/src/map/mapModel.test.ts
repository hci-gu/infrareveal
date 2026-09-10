import { describe, expect, it } from 'vitest'
import type { GatewayData } from '@infrareveal/session-state'
import { buildMapTimelineScene, projectMapFrame } from './mapModel'

const start = Date.parse('2026-09-02T10:00:00Z')
const origin = { latitude: 57.69226, longitude: 11.91737, label: 'Gateway' }

describe('map timeline projection', () => {
  it('reveals destinations and activity according to cursor time', () => {
    const scene = buildMapTimelineScene(fixture(), origin)

    expect(projectMapFrame(scene, start - 1).points).toHaveLength(0)
    expect(projectMapFrame(scene, start + 2_000)).toMatchObject({
      seenFlowCount: 1,
      activeFlowCount: 1,
      byteCount: 1250,
    })
    expect(projectMapFrame(scene, start + 20_000)).toMatchObject({
      seenFlowCount: 1,
      activeFlowCount: 0,
    })
  })

  it('does not reveal traceroute hops before the route completed', () => {
    const scene = buildMapTimelineScene(fixture(), origin)
    const beforeRoute = projectMapFrame(scene, start + 2_000)
    const afterRoute = projectMapFrame(scene, start + 4_000)

    expect(beforeRoute.arcs).toHaveLength(1)
    expect(beforeRoute.arcs[0].gap).toBe(true)
    expect(beforeRoute.hops).toHaveLength(0)
    expect(afterRoute.arcs).toHaveLength(2)
    expect(afterRoute.arcs[0].targetPosition).toEqual([13.2, 55.6])
    expect(afterRoute.hops).toHaveLength(1)
    expect(afterRoute.arcs[0].progressStart).toBe(0)
    expect(afterRoute.arcs[0].progressEnd).toBe(afterRoute.arcs[1].progressStart)
    expect(afterRoute.arcs[1].progressEnd).toBe(1)
    expect(projectMapFrame(scene, start + 2_000)).toEqual(beforeRoute)
    expect(projectMapFrame(scene, start + 4_000, 5000, 1).arcs).toHaveLength(0)
  })

  it('reveals a partial prefix before destination enrichment and honors timed invalidation', () => {
    const data = fixture()
    data.destinations = []
    const partial = {...data.routes[0], complete: false, completed_at: '', available_at: new Date(start + 2000).toISOString(), valid_until: new Date(start + 60_000).toISOString(), status: 'probing' as const}
    data.routes = [partial, {...partial, id: 'invalidated', hops: [], status: 'invalidated', available_at: new Date(start + 4000).toISOString()}]
    const scene = buildMapTimelineScene(data, origin)
    expect(projectMapFrame(scene, start + 1500).arcs).toHaveLength(0)
    const progressive = projectMapFrame(scene, start + 3000)
    expect(progressive.points).toHaveLength(0)
    expect(progressive.arcs).toHaveLength(1)
    expect(progressive.arcs[0].targetPosition).toEqual([13.2, 55.6])
    expect(projectMapFrame(scene, start + 5000).arcs).toHaveLength(0)
    expect(projectMapFrame(scene, start + 3000)).toEqual(progressive)
  })

  it('does not reuse a probe from another session' , () => {
    const data = fixture()
    data.routes[0].session = 'other-session'
    const frame = projectMapFrame(buildMapTimelineScene(data, origin), start + 4_000)
    expect(frame.hops).toHaveLength(0)
    expect(frame.arcs).toHaveLength(1)
    expect(frame.arcs[0].routeId).toBeUndefined()
  })

  it('aggregates flows by destination and ignores ungeolocated destinations', () => {
    const data = fixture()
    data.flows.push({ ...data.flows[0], id: 'flow-2', source_port: 50001 })
    data.destinations.push({ ...data.destinations[0], id: 'missing', ip: '192.0.2.2', lat: 0, lon: 0 })
    data.flows.push({ ...data.flows[0], id: 'flow-3', destination_ip: '192.0.2.2' })
    const scene = buildMapTimelineScene(data, origin)
    const frame = projectMapFrame(scene, start + 2_000)

    expect(scene.endpoints).toHaveLength(1)
    expect(frame.points).toHaveLength(1)
    expect(frame.points[0].flowCount).toBe(2)
  })

  it('hides invalid direct destinations in both route modes while retaining valid router hops', () => {
    const data = fixture()
    data.destinations[0].lat = 95
    data.destinations[0].lon = 200
    const scene = buildMapTimelineScene(data, origin)
    const direct = projectMapFrame({ ...scene, endpoints: scene.endpoints.map(endpoint => ({ ...endpoint, routes: [] })) }, start + 4000)
    expect(direct.points).toHaveLength(0)
    expect(direct.arcs).toHaveLength(0)
    const traced = projectMapFrame(scene, start + 4000)
    expect(traced.points).toHaveLength(0)
    expect(traced.arcs).toHaveLength(1)
    expect(traced.arcs[0].targetPosition).toEqual([13.2, 55.6])
    data.routes = []
    expect(buildMapTimelineScene(data, origin).endpoints).toHaveLength(0)
  })
})

function fixture(): GatewayData {
  return {
    sessions: [],
    selectedSession: {
      id: 'session-1',
      created: '2026-09-02T10:00:00Z',
      updated: '2026-09-02T10:01:00Z',
      started_at: '2026-09-02T10:00:00Z',
      ended_at: '2026-09-02T10:01:00Z',
      name: 'Test session',
      active: false,
    },
    flows: [{
      id: 'flow-1',
      created: '2026-09-02T10:00:01Z',
      updated: '2026-09-02T10:00:10Z',
      session: 'session-1',
      client_ip: '10.0.0.2',
      destination_ip: '192.0.2.1',
      source_port: 50000,
      destination_port: 443,
      protocol: 'tcp',
      state: 'closed',
      start: '2026-09-02T10:00:01Z',
      last_seen: '2026-09-02T10:00:10Z',
      bytes_out: 250,
      bytes_in: 1000,
      packets_out: 2,
      packets_in: 4,
    }],
    destinations: [{
      id: 'destination-1',
      created: '2026-09-02T10:00:01Z',
      ip: '192.0.2.1',
      reverse_dns: 'example.test',
      asn: 64500,
      organization: 'Example',
      provider_label: 'Example Cloud',
      city: 'Malmö',
      country: 'Sweden',
      lat: 55.605,
      lon: 13.0038,
      last_seen: '2026-09-02T10:00:10Z',
    }],
    routes: [{
      id: 'route-1',
      session: 'session-1',
      destination: 'destination-1',
      destination_ip: '192.0.2.1',
      destination_port: 443,
      protocol: 'tcp',
      method: 'tcp:443',
      hops: [{ ttl: 1, address: '192.0.2.254', missing: false, timings: [2], lat: 55.6, lon: 13.2 }],
      complete: true,
      error: '',
      completed_at: '2026-09-02T10:00:03Z',
    }],
    dnsQueries: [],
    attributions: [],
    activityEpisodes: [],
    flowAssociations: [],
    flowActivityChunks: [],
    flowActivityWindows: [],
    flowActivityStatuses: [],
    gateEvents: [],
  }
}
