import { describe, expect, it } from 'vitest'
import { buildMapTimelineScene, projectMapFrame, type MapArc } from './mapModel'
import { buildMapTrackCatalog, type MapSeries } from './mapTracks'
import { createTrafficProfileCache, indexMapTraffic } from './mapTraffic'
import { projectWorkspace } from './mapWorkspace'
import { createMapGeometryCache, sameTrafficArcGeometry } from './mapGeometryCache'
import { createWireWaveformCache } from './wireWaveform'
import fixture from '../../../testdata/aggregate-window-v2.json'
import { seriesKey, type TrafficChunk, type MapWindow, type SessionManifest } from '@infrareveal/session-state'
import { indexDestinationVolumes } from './destinationVolumes'
import { parseMapPreferences } from './mapPreferences'

const connection: MapArc = { id: 'a', endpointId: 'e', trackId: 't', sourcePosition: [12, 57], targetPosition: [-74, 41] }
describe('map work independent of the animation clock', () => {
  it('reuses unchanged geometry, but invalidates changed destinations', () => {
    const geometry = createMapGeometryCache()
    const first = geometry([connection])
    expect(first.connections).toHaveLength(1)
    expect(geometry([{ ...connection }])).toBe(first)
    expect(geometry([{ ...connection, targetPosition: [15, 50] }])).not.toBe(first)
    const changedTrack = geometry([{ ...connection, trackId: 'another-track' }])
    expect(changedTrack.connections[0].trackIds).toEqual(['another-track'])
    expect(changedTrack.connections[0].id).toBe(first.connections[0].id)
  })

  it('reuses a waveform across playhead projections and refreshes changed capture', () => {
    const waveform = createWireWaveformCache()
    const chunk = fixture.window.series[0] as TrafficChunk
    const id = seriesKey(chunk)
    const connection = { id, startMs: chunk.start_ms, endMs: chunk.start_ms + 100, bytes: 10 } as MapSeries
    const index = indexDestinationVolumes([chunk], chunk.start_ms, fixture.window.coverage)
    const range = { from: chunk.start_ms, to: chunk.start_ms+100 }
    const first = waveform([connection], index, range)
    expect(waveform([{ ...connection, bytes: 100 }], Object.assign(new Map(index), { fromMs: index.fromMs, coverage: index.coverage }), range)).toBe(first)
    expect(waveform([{ ...connection, endMs: connection.endMs + 1000 }], index, range)).toBe(first)
    const revised = new Map(index)
    revised.set(id, { ...index.get(id)!, intervals: [] })
    expect(waveform([connection], revised, range)).not.toBe(first)
  })

  it('keeps geometry attributes for rate updates, but invalidates changed directions or paths', () => {
    const arc = { ...connection, endpointIds: ['e'], trackIds: ['t'], direction: 1, radii: Array(12).fill(1) }
    expect(sameTrafficArcGeometry([{ ...arc, radii: Array(12).fill(3) }], [arc])).toBe(true)
    expect(sameTrafficArcGeometry([{ ...arc, direction: -1 }], [arc])).toBe(false)
    expect(sameTrafficArcGeometry([{ ...arc, targetPosition: [15, 50] }], [arc])).toBe(false)
    expect(sameTrafficArcGeometry([{ ...arc, trackIds: ['another-track'] }], [arc])).toBe(false)
  })


  it('reuses rate profiles through metadata updates and refreshes capture and availability', () => {
    const window = fixture.window as MapWindow
    const scene = buildMapTimelineScene(buildMapTrackCatalog(window), fixture.manifest as SessionManifest, { latitude: 57.7, longitude: 11.9, label: 'Gateway' })
    const index = indexMapTraffic(window.series, window.coverage)
    const anchor = window.from_ms + 500
    const profiles = createTrafficProfileCache()
    const first = profiles(scene, index, anchor)
    expect([...first.values()].some(profile => profile.rates.some(rate => rate > 0))).toBe(true)
    const updated = { ...scene, sessionName: 'Updated name', endpoints: scene.endpoints.map(endpoint => ({ ...endpoint, label: 'Updated label', series: endpoint.series.map(series => ({ ...series, bytes: 99999 })) })) }
    expect(profiles(updated, index, anchor)).toBe(first)
    const unavailable = { ...scene, endpoints: scene.endpoints.map(endpoint => ({ ...endpoint, availableFromMs: anchor + 1 })) }
    expect(profiles(unavailable, index, anchor).size).toBe(0)
    const changedCapture = indexMapTraffic([], window.coverage)
    const silent = profiles(scene, changedCapture, anchor)
    expect(silent).not.toBe(first)
    expect([...silent.values()].every(profile => profile.rates.every(rate => rate === 0))).toBe(true)
    const shifted = profiles(scene, index, anchor + 500)
    expect(shifted).not.toBe(first)
    expect([...shifted.values()].some(profile => profile.rates[1] > 0)).toBe(true)
    const shortened = { ...scene, endpoints: scene.endpoints.map(endpoint => ({ ...endpoint, series: endpoint.series.map(series => ({ ...series, endMs: series.startMs })) })) }
    expect(profiles(shortened, index, anchor + 500)).not.toBe(shifted)
  })

  it('keeps every mapped endpoint beyond the former 4,000-connection cutoff', () => {
    const count = 5000
    const window = { ...fixture.window, series: Array.from({ length: count }, (_, i) => ({ ...fixture.window.series[0], id: `chunk-${i}`, client_id: `client-${i}` })) } as MapWindow
    const catalog = buildMapTrackCatalog(window)
    const scene = buildMapTimelineScene(catalog, fixture.manifest as SessionManifest, { latitude: 57.7, longitude: 11.9, label: 'Gateway' })
    const index = indexDestinationVolumes(window.series, window.from_ms, window.coverage)
    const cursor = window.from_ms + 500
    const overview = projectWorkspace(catalog, scene, index, cursor, { locationId: null, expanded: false })
    const frame = projectMapFrame(overview.scene, cursor)
    expect(overview.rows).toHaveLength(count)
    expect(frame.points).toHaveLength(count)
    expect(frame.arcs).toHaveLength(count)
    expect(new Set(frame.arcs.map(arc => arc.endpointId)).size).toBe(count)
    expect(overview.total.received).toBe(overview.rows[0].received * count)
  })

  it('ignores legacy rendering detail while preserving display preferences', () => {
    expect(parseMapPreferences(null)).toEqual({ projection: 'equal-earth', theme: 'dark', labels: true })
    expect(parseMapPreferences(JSON.stringify({ projection: 'mercator', theme: 'light', labels: false, quality: 'raspberry-pi' })))
      .toEqual({ projection: 'mercator', theme: 'light', labels: false })
  })
})
