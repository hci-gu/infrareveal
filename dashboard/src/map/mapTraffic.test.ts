import { describe, expect, it } from 'vitest'
import type { FlowActivityChunk } from '@infrareveal/session-state'
import type { MapTimelineScene } from './mapModel'
import { bundleMapArcs } from './bundleMapArcs'
import { projectMapFrame } from './mapModel'
import { indexMapTraffic, projectTrafficProfiles, trafficRadius, volumeArcs } from './mapTraffic'

const start = Date.parse('2026-09-10T12:00:00Z')
const scene: MapTimelineScene = {
  sessionId: 'session', sessionName: 'Traffic', startMs: start, endMs: start + 20_000,
  origin: { longitude: 12, latitude: 57, label: 'Gateway' }, totalFlowCount: 1,
  endpoints: [{ id: 'a', ip: '192.0.2.1', label: 'a', provider: '', city: '', country: '', position: [18, 59], availableFromMs: start, firstSeenMs: start, lastSeenMs: start + 10_000, routes: [],
    flows: [{ id: 'flow', startMs: start, endMs: start + 10_000, bytes: 1_000_000, packets: 1000 }],
  }],
}
function chunk(rows: number[][], bucketMs = 500): FlowActivityChunk {
  return { id: 'chunk', session: 'session', flow: 'flow', flow_key: 'key', chunk_start: new Date(start).toISOString(), bucket_ms: bucketMs, chunk_ms: 10_000,
    samples: { version: 1, bucket_ms: bucketMs, chunk_ms: 10_000, samples: rows },
    wire_bytes_out: 0, wire_bytes_in: 0, payload_bytes_out: 0, payload_bytes_in: 0, packets_out: 0, packets_in: 0, tcp_flags_out: 0, tcp_flags_in: 0,
    capture_complete: true, dropped_events: 0, updated_at_source: new Date(start + 10_000).toISOString(),
  }
}
function profile(chunks: FlowActivityChunk[], time = 2000) {
  return projectTrafficProfiles(scene, indexMapTraffic(chunks), start + time).get('a')!
}

describe('traffic volume profiles', () => {
  it('distinguishes a tiny exchange from a stream using the same radius scale', () => {
    expect(trafficRadius(1_000_000)).toBeGreaterThan(trafficRadius(256) * 8)
    expect(trafficRadius(0)).toBe(0)
    expect(trafficRadius(0, 1)).toBeGreaterThan(0)
    expect(trafficRadius(Number.NaN)).toBe(0)
    expect(trafficRadius(1e12)).toBe(16)
  })

  it('uses current payload rate rather than the lifetime total', () => {
    expect(profile([chunk([[1500, 200, 300, 1, 1]])])).toMatchObject({ rates: [1000, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], source: 'sampled' })
  })

  it('retains short 50 ms bursts anywhere inside the 500 ms display bucket', () => {
    expect(profile([chunk([[1500, 0, 5000, 0, 5], [1950, 0, 5000, 0, 5]], 50)]).rates[0]).toBe(20_000)
  })

  it('does not count overlapping coarse and fine samples twice', () => {
    expect(profile([chunk([[1500, 0, 100_000, 0, 50]]), chunk([[1500, 0, 1000, 0, 1]], 50)]).rates[0]).toBe(2000)
  })

  it('keeps silence thin, without falling back to lifetime bytes', () => {
    const result = profile([chunk([])])
    expect(result.rates.every((rate) => rate === 0)).toBe(true)
    expect(result.source).toBe('sampled')
  })

  it('labels missing and incomplete measurements honestly', () => {
    expect(profile([]).source).toBe('estimated')
    expect(profile([]).rates[0]).toBe(100_000)
    expect(profile([{ ...chunk([]), capture_complete: false }]).source).toBe('partial')
    expect(profile([{ ...chunk([]), chunk_start: new Date(start + 5000).toISOString() }]).rates[0]).toBe(0)
  })

  it('moves burst history along the route and reproduces it when seeking back', () => {
    const chunks = [chunk([[1500, 0, 10_000, 0, 5]])]
    const atTwo = profile(chunks, 2000)
    expect(profile(chunks, 2500).rates[1]).toBe(atTwo.rates[0])
    expect(profile(chunks, 2000)).toEqual(atTwo)
    expect(profile(chunks, 1000).rates.every((rate) => rate === 0)).toBe(true)
  })

  it('sums co-located endpoint rates before scaling the bulge', () => {
    const other = { ...scene.endpoints[0], id: 'b', ip: '192.0.2.2', flows: [{ ...scene.endpoints[0].flows[0], id: 'flow-b' }] }
    const combined = { ...scene, endpoints: [...scene.endpoints, other] }
    const index = indexMapTraffic([chunk([[1500, 0, 5000, 0, 5]]), { ...chunk([[1500, 0, 5000, 0, 5]]), flow: 'flow-b', id: 'b' }])
    const routes = bundleMapArcs(projectMapFrame(combined, start + 2000).arcs)
    const arcs = volumeArcs(routes, projectTrafficProfiles(combined, index, start + 2000))
    expect(arcs).toHaveLength(1)
    expect(arcs[0].radii[0]).toBe(trafficRadius(20_000, 20))
  })

  it('leaves a thin connection after flow activity has ended', () => {
    const frame = projectMapFrame(scene, start + 20_000)
    expect(frame.arcs).toHaveLength(1)
    expect(frame.activeFlowCount).toBe(0)
    expect(volumeArcs(bundleMapArcs(frame.arcs), projectTrafficProfiles(scene, new Map(), start + 20_000))).toHaveLength(0)
  })

  it('rejects malformed samples without treating them as measured silence', () => {
    expect(profile([{ ...chunk([]), samples: { version: 2, samples: [] } }]).source).toBe('estimated')
    expect(profile([chunk([[1500, -1, 0, 0, 0]])]).source).toBe('partial')
  })
})
