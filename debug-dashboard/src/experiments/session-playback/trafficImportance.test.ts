import { describe, expect, it } from 'vitest'
import type { Flow, FlowActivityChunk, FlowActivityWindow } from '@infrareveal/session-state'
import type { TimelineClip } from '../../model/sessionModel'
import type { TrafficGroup } from './trafficModel'
import { importanceLayout, trafficVolumes } from './trafficImportance'

const epoch = Date.parse('2026-09-10T11:00:00Z')
const iso = (ms: number) => new Date(epoch + ms).toISOString()
const flow = (id: string, bytes_in = 1000): Flow => ({ id, session: 's', created: iso(0), updated: iso(60_000), client_ip: 'phone', destination_ip: '1.1.1.1', source_port: 5000, destination_port: 443, protocol: 'tcp', state: 'CLOSE', start: iso(0), last_seen: iso(60_000), bytes_in, bytes_out: 100, packets_in: 1, packets_out: 1 })
const chunk = (id: string, flow: string, start: number, bytes: number, bucket_ms = 1000): FlowActivityChunk => ({ id, session: 's', flow, flow_key: flow, chunk_start: iso(start), bucket_ms, chunk_ms: 5000, samples: { version: 1, samples: [[0, 100, bytes, 1, 1]] }, wire_bytes_in: bytes, wire_bytes_out: 100, payload_bytes_in: bytes, payload_bytes_out: 100, packets_in: 1, packets_out: 1, tcp_flags_in: 0, tcp_flags_out: 0, capture_complete: true, dropped_events: 0, updated_at_source: iso(start) })
const coverage: FlowActivityWindow = { id: 'w', session: 's', window_key: 'w', window_start: iso(0), window_ms: 60_000, capture_running: true, capture_complete: true, dropped_events: 0, last_error: '' }
const group = (id: string, ids: string[]): TrafficGroup => ({ id, label: id, client: 'phone', clips: ids.map(flowId => ({ flowId, startMs: epoch } as TimelineClip)), dns: [], attributions: [], associations: [] })

describe('Traffic importance', () => {
  it('uses full received + sent counters only in session-data mode', () => {
    const flows = new Map([['a', flow('a')], ['unknown', flow('unknown', NaN)]])
    const volumes = trafficVolumes(flows, 'total', [], [], epoch)
    expect(volumes.get('a')).toEqual({ bytes: 1100, complete: true })
    expect(volumes.get('unknown')).toEqual({ bytes: null, complete: false })
    expect(trafficVolumes(flows, 'recent', [], [], epoch + 10_000).get('a')?.bytes).toBeNull()
  })

  it('changes the leader as captured bytes enter and leave the trailing window, including backward seeks', () => {
    const flows = new Map([['a', flow('a')], ['b', flow('b')]])
    const chunks = [chunk('early', 'a', 5000, 9000), chunk('late', 'b', 35_000, 20_000)]
    const groups = [group('activity', ['b', 'a'])]
    const at = (time: number) => importanceLayout(groups, trafficVolumes(flows, 'recent', chunks, [coverage], epoch + time), 'recent', 65)
    expect(at(10_000).groups[0].clips.map(c => c.flowId)).toEqual(['a', 'b'])
    expect(at(40_000).groups[0].clips.map(c => c.flowId)).toEqual(['b', 'a'])
    expect(at(40_000).height('a')).toBe(36)
    expect(at(10_000).height('a')).toBeGreaterThan(at(10_000).height('b'))
  })

  it('excludes future and partial boundary buckets and never double-counts detail levels', () => {
    const flows = new Map([['a', flow('a')]])
    const chunks = [chunk('coarse', 'a', 5000, 9000), chunk('fine', 'a', 5000, 9000, 50)]
    const at = (time: number) => trafficVolumes(flows, 'recent', chunks, [coverage], epoch + time).get('a')?.bytes
    expect(at(5025)).toBe(0)
    expect(at(5050)).toBe(9100)
    expect(at(10_000)).toBe(9100)
    expect(at(35_025)).toBe(0)
  })

  it('distinguishes silence from missing or partial capture', () => {
    const flows = new Map([['a', flow('a')]])
    expect(trafficVolumes(flows, 'recent', [], [coverage], epoch + 40_000).get('a')).toEqual({ bytes: 0, complete: true })
    expect(trafficVolumes(flows, 'recent', [], [], epoch + 40_000).get('a')).toEqual({ bytes: null, complete: false })
    expect(trafficVolumes(flows, 'recent', [chunk('partial', 'a', 35_000, 900)], [{ ...coverage, capture_complete: false }], epoch + 40_000).get('a')).toEqual({ bytes: 1000, complete: false })
  })

  it('sorts groups by their filtered total and flows by volume, with bounded heights and stable ties', () => {
    const groups = [group('small', ['b', 'a']), group('large', ['d', 'c']), group('dns', [])]
    const volumes = new Map([['a', { bytes: 100, complete: true }], ['b', { bytes: 100, complete: true }], ['c', { bytes: 10_000, complete: true }], ['d', { bytes: null, complete: false }]])
    const layout = importanceLayout(groups, volumes, 'total', 100)
    expect(layout.groups.map(g => g.id)).toEqual(['large', 'small', 'dns'])
    expect(layout.groups[0].clips.map(c => c.flowId)).toEqual(['c', 'd'])
    expect(layout.groups[1].clips.map(c => c.flowId)).toEqual(['a', 'b'])
    expect(layout.totalBytes).toBe(10_200)
    expect(layout.height('c')).toBe(124)
    expect(layout.height('d')).toBe(36)
    expect(layout.height('a')).toBe(45)
    expect(importanceLayout(groups, volumes, 'total', 0).height('c')).toBe(36)
    expect(importanceLayout(groups, volumes, 'equal', 100).groups).toBe(groups)
    expect(importanceLayout(groups, volumes, 'equal', 100).height('c')).toBe(36)
    expect(groups[0].clips.map(c => c.flowId)).toEqual(['b', 'a'])
  })
})
