import { describe, expect, it } from 'vitest'
import { flowTrackAt, indexFlowTracks } from '@infrareveal/session-state'
import type { ActivityEpisode, Flow, FlowAssociation, GatewayData } from '@infrareveal/session-state'
import { buildMapTrackCatalog, projectMapTracks, sceneForTracks, TrackColors, trackOpacity } from './mapTracks'
import { buildMapTimelineScene, projectMapFrame } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'
import { projectTrafficProfiles, volumeArcs } from './mapTraffic'

const epoch = Date.parse('2026-09-10T10:00:00Z')
const iso = (ms: number) => new Date(epoch + ms).toISOString()
const origin = { longitude: 12, latitude: 57, label: 'Gateway' }
const flow = (id: string, patch: Partial<Flow> = {}): Flow => ({ id, session: 's', client_ip: '10.42.0.2', destination_ip: '203.0.113.10', source_port: 50000, destination_port: 443, protocol: 'tcp', state: 'ESTABLISHED', start: iso(0), last_seen: iso(10000), created: iso(0), updated: iso(10000), bytes_in: 9000, bytes_out: 1000, packets_in: 90, packets_out: 10, ...patch })
const episode = (id: string, label: string): ActivityEpisode => ({ id, session: 's', episode_key: id, client_ip: '10.42.0.2', site_key: label, label, anchor_hostname: `www.${label}`, start: iso(0), last_seen: iso(10000), confidence: 'high', explanation: 'Client activity evidence' })
const association = (id: string, flowId: string, episodeId: string, patch: Partial<FlowAssociation> = {}): FlowAssociation => ({ id, session: 's', flow: flowId, episode: episodeId, parent_site_key: episodeId, parent_label: episodeId, relationship: 'first_party', confidence: 'high', score: .9, explanation: 'Observed first-party activity', observed_at: iso(1000), ...patch })
function fixture(): GatewayData {
  return { sessions: [], selectedSession: null, flows: [flow('svt'), flow('youtube', { bytes_in: 99000 })], activityEpisodes: [episode('svt', 'svt.se'), episode('youtube', 'youtube.com')], flowAssociations: [association('a', 'svt', 'svt'), association('b', 'youtube', 'youtube')], attributions: [], dnsQueries: [], flowActivityChunks: [], flowActivityWindows: [], flowActivityStatuses: [], gateEvents: [], routes: [], destinations: [{ id: 'shared-cdn', ip: '203.0.113.10', reverse_dns: 'cdn.example.net', asn: 64500, organization: 'Shared CDN', provider_label: 'Shared CDN', city: 'Stockholm', country: 'SE', lat: 59.3, lon: 18.1, last_seen: iso(10000), created: iso(0) }] }
}
function project(data: GatewayData, time = 5000, colors = new TrackColors()) {
  const scene = buildMapTimelineScene(data, origin, epoch)
  const catalog = buildMapTrackCatalog(data, colors)
  const frame = projectMapTracks(catalog, scene, epoch + time)
  const groupedScene = sceneForTracks(scene, frame.byFlow)
  return { scene, catalog, frame, groupedScene }
}

describe('shared activity tracks on the map', () => {
  it('uses the debug dashboard identity and separates two sites sharing an IP', () => {
    const data = fixture(), { catalog, frame, groupedScene } = project(data)
    expect(frame.tracks.map(track => track.label)).toEqual(['youtube.com', 'svt.se'])
    for (const track of frame.tracks) expect(track.id).toBe(flowTrackAt(catalog.index, track.connections[0].flow).id)
    expect(groupedScene.endpoints).toHaveLength(2)
    const arcs = bundleMapArcs(projectMapFrame(groupedScene, epoch + 5000).arcs)
    expect(arcs).toHaveLength(2)
    expect(new Set(arcs.map(arc => arc.height)).size).toBe(2)
    expect(frame.tracks[0].color).not.toEqual(frame.tracks[1].color)
  })

  it('keeps each connection in exactly one track and measures only its own traffic', () => {
    const { frame, groupedScene } = project(fixture())
    expect(frame.tracks.reduce((sum, track) => sum + track.connections.length, 0)).toBe(2)
    expect(frame.tracks.reduce((sum, track) => sum + track.bytes, 0)).toBe(110000)
    const arcs = volumeArcs(bundleMapArcs(projectMapFrame(groupedScene, epoch + 5000).arcs), projectTrafficProfiles(groupedScene, new Map(), epoch + 5000))
    expect(arcs.map(arc => arc.peakBytesPerSecond).sort((a, b) => a - b)).toEqual([1000, 10000])
  })

  it('routes only the matching socket when a track shares an IP across protocols and ports', () => {
    const data = fixture()
    data.flows = [flow('tcp'), flow('udp', { protocol: 'udp', bytes_in: 99000 }), flow('other-port', { destination_port: 8443 })]
    data.flowAssociations = data.flows.map(f => association(`a-${f.id}`, f.id, 'svt'))
    data.routes = [{ id: 'tcp-route', session: 's', destination: 'shared-cdn', destination_ip: '203.0.113.10', destination_port: 443, protocol: 'tcp', method: 'tcp:443', complete: false, error: '', completed_at: iso(3000), hops: [{ ttl: 1, address: '198.51.100.1', missing: false, lat: 55, lon: 10, timings: [2] }] }]
    const { groupedScene } = project(data)
    const routed = groupedScene.endpoints.find(endpoint => endpoint.routes.length)!
    expect(routed.flows.map(f => f.id)).toEqual(['tcp'])
    expect(groupedScene.endpoints.flatMap(endpoint => endpoint.flows)).toHaveLength(3)
    const before = projectMapFrame(groupedScene, epoch + 2000)
    expect(before.hops).toHaveLength(0)
    const after = projectMapFrame(groupedScene, epoch + 5000)
    expect(after.arcs.filter(arc => arc.routeId === 'tcp-route')).toHaveLength(2)
    expect(after.arcs.filter(arc => !arc.routeId)).toHaveLength(1)
    const arcs = volumeArcs(bundleMapArcs(after.arcs), projectTrafficProfiles(groupedScene, new Map(), epoch + 5000))
    expect(arcs.filter(arc => arc.routeId).map(arc => arc.peakBytesPerSecond)).toEqual([1000, 1000])
    expect(arcs.find(arc => !arc.routeId)?.peakBytesPerSecond).toBe(11000)
  })

  it('waits for association evidence and keeps replay deterministic', () => {
    const data = fixture()
    expect(project(data, -1).frame.tracks).toHaveLength(0)
    expect(project(data, 500).frame.tracks[0].label).toBe('Independent traffic')
    expect(project(data, 5000).frame.tracks).toHaveLength(2)
    expect(project(data, 500).frame.tracks[0].label).toBe('Independent traffic')
  })

  it('does not infer parent activities from providers, low confidence or another client', () => {
    const data = fixture()
    data.flows.push(flow('other', { client_ip: '10.42.0.3' }))
    data.flowAssociations = [association('low', 'svt', 'svt', { confidence: 'low' }), association('wrong-client', 'other', 'svt')]
    const { frame } = project(data)
    expect(frame.tracks.every(track => track.label === 'Independent traffic')).toBe(true)
    expect(new Set(frame.tracks.map(track => track.client)).size).toBe(2)
  })

  it('includes unmapped connections in the inspector totals', () => {
    const data = fixture()
    data.flows.push(flow('unmapped', { destination_ip: '198.51.100.4' }))
    data.flowAssociations.push(association('c', 'unmapped', 'svt'))
    const { frame, groupedScene } = project(data)
    const track = frame.tracks.find(track => track.label === 'svt.se')!
    expect(track.connections).toHaveLength(2)
    expect(track.mappedCount).toBe(1)
    expect(track.bytes).toBe(20000)
    expect(groupedScene.endpoints.flatMap(endpoint => endpoint.flows)).toHaveLength(2)
  })

  it('keeps assigned colors stable through live additions and ordering changes', () => {
    const colors = new TrackColors(), data = fixture(), before = project(data, 5000, colors).frame.tracks
    data.flows.reverse()
    data.flows.push(flow('new', { client_ip: '10.42.0.4' }))
    const after = project(data, 5000, colors).frame.tracks
    for (const track of before) expect(after.find(item => item.id === track.id)?.color).toEqual(track.color)
    expect(trackOpacity(before[0].id, before[0].id)).toBe(1)
    expect(trackOpacity(before[1].id, before[0].id)).toBeLessThan(.1)
    expect(trackOpacity(before[1].id, null)).toBe(1)
  })

  it('keeps hostname evidence separate from activity membership and hides future names', () => {
    const data = fixture()
    data.attributions = [{ id: 'host', session: 's', flow: 'svt', candidate_hostname: 'video.cdn.example.net', source_signal: 'dns_answer', confidence: 'high', explanation: 'DNS match', dns_query: '', observed_at: iso(4000) }]
    const index = indexFlowTracks(data)
    expect(flowTrackAt(index, data.flows[0], epoch + 3000).hostname).toBe('203.0.113.10')
    expect(flowTrackAt(index, data.flows[0], epoch + 5000)).toMatchObject({ label: 'svt.se', hostname: 'video.cdn.example.net' })
    data.attributions[0].confidence = 'hidden'
    expect(flowTrackAt(indexFlowTracks(data), data.flows[0], epoch + 5000).hostname).toBe('203.0.113.10')
  })
})
