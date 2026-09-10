import { afterEach, describe, expect, it, vi } from 'vitest'
import { emptyGatewayData } from '@infrareveal/session-state'
import type { Flow } from '@infrareveal/session-state'
import { buildMapTimelineScene } from './mapModel'
import { buildMapTrackCatalog, projectMapTracks, sceneForTracks } from './mapTracks'
import { columnMetersPerPixel, connectionVolume, destinationHeight, indexDestinationVolumes, projectDestinationVolumes } from './destinationVolumes'
import type { VolumeChunk } from './destinationVolumes'
import { readVolumeChunks } from './useDestinationVolumes'

const epoch = Date.parse('2026-09-10T10:00:00Z')
const iso = (ms: number) => new Date(epoch + ms).toISOString()
const chunk = (patch: Partial<VolumeChunk> = {}): VolumeChunk => ({ id: 'c1', session: 's', flow: 'f1', chunk_start: iso(0), chunk_ms: 5000, wire_bytes_in: 4000, wire_bytes_out: 1000, capture_complete: true, dropped_events: 0, updated_at_source: iso(5000), updated: iso(5000), ...patch })
function fixture() {
  const flow: Flow = { id: 'f1', session: 's', client_ip: '10.42.0.2', destination_ip: '203.0.113.1', source_port: 50000, destination_port: 443, protocol: 'tcp', state: 'ESTABLISHED', start: iso(0), last_seen: iso(10_000), created: iso(0), updated: iso(10_000), bytes_in: 8000, bytes_out: 2000, packets_in: 8, packets_out: 2 }
  const destination = { id: 'd1', ip: flow.destination_ip, reverse_dns: '', asn: 64500, organization: '', provider_label: '', city: 'Stockholm', country: 'SE', lat: 59.3, lon: 18.1, last_seen: iso(10_000), created: iso(0) }
  const data = { ...emptyGatewayData(), flows: [flow, { ...flow, id: 'f2', client_ip: '10.42.0.3', destination_ip: '203.0.113.2' }], destinations: [destination, { ...destination, id: 'd2', ip: '203.0.113.2' }] }
  const scene = buildMapTimelineScene(data, { longitude: 12, latitude: 57, label: 'Gateway' }, epoch)
  const connections = projectMapTracks(buildMapTrackCatalog(data), scene, epoch + 10_000).byFlow
  return { scene, connections, connection: connections.get('f1')! }
}

describe('accumulated destination traffic', () => {
  it('interpolates current chunks, sums completed ones, and preserves direction', () => {
    const { connection } = fixture()
    const index = indexDestinationVolumes([chunk(), chunk({ id: 'c2', chunk_start: iso(5000), updated_at_source: iso(10_000) })])
    expect(connectionVolume(connection, index, epoch - 1)).toMatchObject({ received: 0, sent: 0 })
    expect(connectionVolume(connection, index, epoch)).toMatchObject({ received: 0, sent: 0 })
    expect(connectionVolume(connection, index, epoch + 2500)).toMatchObject({ received: 2000, sent: 500, estimated: false })
    expect(connectionVolume(connection, index, epoch + 7500)).toMatchObject({ received: 6000, sent: 1500 })
    const end = connectionVolume(connection, index, epoch + 10_000)
    expect(end).toMatchObject({ received: 8000, sent: 2000 })
    expect(connectionVolume(connection, index, epoch + 100_000)).toEqual(end)
    expect(connectionVolume(connection, index, epoch + 2500)).toMatchObject({ received: 2000, sent: 500 })
  })

  it('stops growing at the last observed packet and preserves gaps as silence', () => {
    const { connection } = fixture()
    const index = indexDestinationVolumes([chunk({ updated_at_source: iso(1000) }), chunk({ id: 'c2', chunk_start: iso(8000), updated_at_source: iso(9000) })])
    expect(connectionVolume(connection, index, epoch + 1000).received).toBe(4000)
    expect(connectionVolume(connection, index, epoch + 7500).received).toBe(4000)
    expect(connectionVolume(connection, index, epoch + 8500).received).toBe(6000)
  })

  it('replaces duplicate revisions and does not count another summary of the same chunk twice', () => {
    const { connection } = fixture()
    const latest = chunk({ wire_bytes_in: 9000, updated: iso(6000) })
    const index = indexDestinationVolumes([latest, chunk(), { ...latest, id: 'coarse' }])
    expect(connectionVolume(connection, index, epoch + 10_000)).toMatchObject({ received: 9000, sent: 1000 })
  })

  it('marks missing history as estimated without revealing final totals immediately', () => {
    const { connection } = fixture()
    expect(connectionVolume(connection, new Map(), epoch + 2500)).toMatchObject({ received: 2000, sent: 500, estimated: true })
    expect(connectionVolume(connection, new Map(), epoch + 10_000)).toMatchObject({ received: 8000, sent: 2000, estimated: true })
    const future = indexDestinationVolumes([chunk({ chunk_start: iso(5000), updated_at_source: iso(10_000) })])
    expect(connectionVolume(connection, future, epoch + 2500)).toMatchObject({ received: 0, sent: 0, estimated: false })
  })

  it('flags partial capture only once those bytes have appeared and rejects malformed counters', () => {
    const { connection } = fixture()
    const partial = indexDestinationVolumes([chunk({ chunk_start: iso(5000), updated_at_source: iso(10_000), dropped_events: 3 })])
    expect(connectionVolume(connection, partial, epoch + 2000).partial).toBe(false)
    expect(connectionVolume(connection, partial, epoch + 8000).partial).toBe(true)
    expect(indexDestinationVolumes([chunk({ wire_bytes_in: -1 }), chunk({ id: 'bad-date', chunk_start: 'invalid' })]).size).toBe(0)
  })

  it('groups co-located IPs into one stack and counts every flow once across route splits', () => {
    const { scene, connections } = fixture()
    const index = indexDestinationVolumes([chunk(), chunk({ id: 'c2', flow: 'f2', wire_bytes_in: 8000 })])
    const split = sceneForTracks(scene, connections)
    const [destination] = projectDestinationVolumes({ ...split, endpoints: [...split.endpoints, split.endpoints[0]] }, connections, index, epoch + 10_000)
    expect(destination).toMatchObject({ received: 12000, sent: 2000, bytes: 14000, flowCount: 2 })
    expect(destination.ips).toHaveLength(2)
    expect(destination.tracks).toHaveLength(2)
    expect(destination.tracks.reduce((sum, track) => sum + track.height, 0)).toBeCloseTo(destination.height)
    expect(destination.tracks[1].base).toBeCloseTo(destination.tracks[0].height)
    expect(projectDestinationVolumes(scene, connections, index, epoch + 10_000, new Set(['203.0.113.1']))[0].bytes).toBe(5000)
    expect(projectDestinationVolumes(scene, connections, index, epoch - 1)).toHaveLength(0)
  })

  it('uses a fixed monotonic scale with consistent size across map zoom and latitude', () => {
    const sizes = [0, 256, 1e3, 1e6, 1e9].map(destinationHeight)
    expect(sizes[0]).toBe(0)
    expect(sizes.every((size, i) => i === 0 || size > sizes[i - 1])).toBe(true)
    expect(columnMetersPerPixel(60, 2)).toBeCloseTo(columnMetersPerPixel(0, 2) / 2)
    expect(columnMetersPerPixel(0, 3)).toBeCloseTo(columnMetersPerPixel(0, 2) / 2)
  })
})

afterEach(() => vi.unstubAllGlobals())
describe('destination summary transport', () => {
  it('paginates compact summaries and filters live updates by storage revision', async () => {
    const first = Array.from({ length: 500 }, (_, i) => chunk({ id: `a${String(i).padStart(3, '0')}` }))
    const fetcher = vi.fn().mockResolvedValueOnce({ ok: true, json: async () => ({ items: first }) }).mockResolvedValueOnce({ ok: true, json: async () => ({ items: [chunk({ id: 'b' }), chunk({ id: 'wrong-session', session: 'other' })] }) })
    vi.stubGlobal('fetch', fetcher)
    const result = await readVolumeChunks('s', epoch + 100_000, new AbortController().signal)
    expect(result).toHaveLength(501)
    const params = new URL(fetcher.mock.calls[1][0]).searchParams
    expect(params.get('fields')).not.toContain('samples')
    expect(params.get('filter')).toContain('id > "a499"')
    expect(params.get('filter')).toContain('updated >= "2026-09-10 10:01:10.000Z"')
  })

  it('does not return incomplete history after a page fails', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({ ok: false, status: 503 }))
    await expect(readVolumeChunks('s', 0, new AbortController().signal)).rejects.toThrow('503')
  })
})
