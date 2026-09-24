import { describe, expect, it } from 'vitest'
import { emptyGatewayData } from '@infrareveal/session-state'
import type { Flow } from '@infrareveal/session-state'
import { buildMapTimelineScene } from './mapModel'
import { buildMapTrackCatalog } from './mapTracks'
import { indexDestinationVolumes, projectDestinationVolumes, directionalColumns } from './destinationVolumes'
import type { VolumeChunk } from './destinationVolumes'
import { projectWorkspace, allowsDirection } from './mapWorkspace'
import { wireWaveform, waveformCeiling } from './wireWaveform'
import { equalEarth } from './equalEarth'
import { parseMapPreferences } from './mapPreferences'

const start = Date.parse('2026-09-24T10:00:00Z')
const iso = (ms: number) => new Date(start + ms).toISOString()
function fixture(from = 0) {
  const flows: Flow[] = Array.from({ length: 3 }, (_, i) => ({ id: `f${i}`, session: 's', client_ip: '10.0.0.2', destination_ip: `203.0.113.${i + 1}`, source_port: 5000 + i, destination_port: 443, protocol: 'tcp', state: 'ESTABLISHED', start: iso(0), last_seen: iso(10_000), created: iso(0), updated: iso(10_000), bytes_in: 900000, bytes_out: 900000, packets_in: 10, packets_out: 10 }))
  const data = { ...emptyGatewayData(), flows, destinations: [
    { id: 'nl', ip: flows[0].destination_ip, reverse_dns: '', asn: 1, organization: '', provider_label: '', country: 'NL', city: 'Amsterdam', lat: 52.4, lon: 4.9, last_seen: iso(10_000), created: iso(0) },
    { id: 'us', ip: flows[1].destination_ip, reverse_dns: '', asn: 1, organization: '', provider_label: '', country: 'US', city: '', lat: 39, lon: -98, last_seen: iso(10_000), created: iso(0) },
  ] }
  const chunks: VolumeChunk[] = flows.map((flow, i) => ({ id: `c${i}`, session: 's', flow: flow.id, chunk_start: iso(0), chunk_ms: 10_000, wire_bytes_in: [9000, 1000, 300][i], wire_bytes_out: [100, 8000, 200][i], capture_complete: true, dropped_events: 0, updated_at_source: iso(10_000), updated: iso(10_000) }))
  const scene = buildMapTimelineScene(data, { longitude: 12, latitude: 57, label: 'Gateway' }, start + from)
  const index = indexDestinationVolumes(chunks, from ? start + from : 0)
  const catalog = buildMapTrackCatalog(data)
  const project = (direction: 'both' | 'received' | 'sent' = 'both', locationId: string | null = null, time = 10_000) => projectWorkspace(catalog, scene, index, start + time, { direction, locationId, expanded: false })
  return { data, chunks, scene, index, catalog, project }
}

describe('direction-aware map workspace', () => {
  it('ranks by selected direction and reconciles locations, tracks, and unlocated totals', () => {
    const { project } = fixture()
    const both = project(), sent = project('sent'), downloaded = project('received')
    expect(both.total).toMatchObject({ received: 10300, sent: 8300, estimated: false })
    expect(downloaded.locations[0].label).toBe('Amsterdam')
    expect(sent.locations[0].id).toBe('country:US')
    expect(both.locations.find(l => l.id === 'unlocated')).toMatchObject({ bytes: 500 })
    expect(both.locations.find(l => l.id === 'unlocated')?.position).toBeUndefined()
    for (const value of [both, sent, downloaded]) {
      expect(value.rows.reduce((sum, row) => sum + row.bytes, 0)).toBe(value.tracks.reduce((sum, track) => sum + track.bytes, 0))
      expect(value.locations.reduce((sum, location) => sum + location.bytes, 0)).toBe(value.rows.reduce((sum, row) => sum + row.bytes, 0))
    }
  })
  it('scopes map flows, timeline, and directional totals to the same location', () => {
    const { project, scene, index } = fixture()
    const selected = project('sent', 'country:US')
    expect([...selected.byFlow.keys()]).toEqual(['f1'])
    expect(selected.scene.endpoints.flatMap(e => e.flows).map(f => f.id)).toEqual(['f1'])
    expect(selected.rows).toHaveLength(1)
    expect(selected.total).toMatchObject({ received: 1000, sent: 8000 })
    const destinations = projectDestinationVolumes(scene, selected.byFlow, index, start + 10_000)
    expect(destinations).toHaveLength(1)
    expect(destinations[0].sent).toBe(selected.total.sent)
    expect(project('both', 'unlocated').rows[0].location).toBe('Unlocated')
  })
  it('preserves replay and rolling retention instead of substituting lifetime counters', () => {
    expect(fixture().project('both', null, 5000).total).toMatchObject({ received: 5150, sent: 4150 })
    expect(fixture(5000).project().total).toMatchObject({ received: 5150, sent: 4150, partial: true })
    expect(fixture(11000).project('both', null, 12000).total.received).toBe(0)
    expect(fixture().project('both', null, -100).locations).toHaveLength(0)
  })
  it('keeps filters stable when an expired location disappears', () => {
    const result = fixture().project('both', 'missing')
    expect(result.byFlow.size).toBe(0)
    expect(result.rows).toHaveLength(0)
    expect(result.total.received).toBe(0)
  })
  it('separates paired column directions and stream direction', () => {
    const { scene, project, index } = fixture()
    const destinations = projectDestinationVolumes(scene, project().byFlow, index, start + 10_000)
    const columns = directionalColumns(destinations, 'both')
    expect(columns.map(c => c.direction)).toEqual([-1, 1])
    expect(directionalColumns(destinations, 'received').every(c => c.direction === -1)).toBe(true)
    expect(allowsDirection('sent', -1)).toBe(false)
    expect(allowsDirection('received', -1)).toBe(true)
  })
})

describe('wire-rate timeline', () => {
  it('uses captured direction counters and conserves bytes across bins', () => {
    const { project, index } = fixture()
    const bins = wireWaveform([...project().byFlow.values()], index, { from: start, to: start + 10_000 }, 4)
    expect(bins).toHaveLength(4)
    expect(bins.reduce((sum, bin) => sum + bin.received * 2.5, 0)).toBeCloseTo(10300)
    expect(bins.reduce((sum, bin) => sum + bin.sent * 2.5, 0)).toBeCloseTo(8300)
    expect(bins.every(bin => bin.complete && bin.observed)).toBe(true)
    expect(waveformCeiling([bins], 'both')).toBe(2000)
  })
  it('does not fabricate a waveform from flow counters or bridge missing capture', () => {
    const { project, chunks } = fixture()
    const connection = project().byFlow.get('f0')!
    expect(wireWaveform([connection], new Map(), { from: start, to: start + 10_000 }, 2)).toEqual([
      { received: 0, sent: 0, complete: false, observed: false }, { received: 0, sent: 0, complete: false, observed: false },
    ])
    const short = indexDestinationVolumes([{ ...chunks[0], chunk_ms: 5000, updated_at_source: iso(5000) }])
    const bins = wireWaveform([connection], short, { from: start, to: start + 10_000 }, 2)
    expect(bins[0].observed).toBe(true)
    expect(bins[1]).toMatchObject({ observed: false, complete: false })
    const partial = indexDestinationVolumes([{ ...chunks[0], dropped_events: 1 }])
    expect(wireWaveform([connection], partial, { from: start, to: start + 10_000 }, 1)[0]).toMatchObject({ observed: true, complete: false })
  })
})

describe('map display settings and geography', () => {
  it('handles invalid persisted settings and preserves supported preferences', () => {
    expect(parseMapPreferences('broken')).toEqual({ projection: 'equal-earth', theme: 'dark', labels: true })
    expect(parseMapPreferences('{"projection":"globe","theme":"invalid","labels":"false"}')).toEqual(parseMapPreferences(null))
    expect(parseMapPreferences('{"projection":"mercator","theme":"system","labels":false}')).toEqual({ projection: 'mercator', theme: 'system', labels: false })
  })
  it('projects poles and antimeridian finitely with symmetric geometry', () => {
    expect(equalEarth([0, 0])).toEqual([500, 280])
    const left = equalEarth([-180, 50]), right = equalEarth([180, 50])
    expect(left[0] + right[0]).toBeCloseTo(1000)
    expect(left[1]).toBeCloseTo(right[1])
    expect(equalEarth([0, 90]).every(Number.isFinite)).toBe(true)
    expect(equalEarth([0, -90])[1] + equalEarth([0, 90])[1]).toBeCloseTo(560)
  })
})
