import { describe, expect, it } from 'vitest'
import { buildSeaNetwork, cableSection, cablesBetween, CABLES, classifySeries, gatewayRegion, regionCrossing, splitAntimeridian, summarizeCrossings } from './seaCrossings'
import type { Cable } from './seaCrossings'
import type { LocationTraffic } from './mapWorkspace'
import type { MapSeries } from './mapTracks'
import type { MapPosition } from './mapModel'

const gothenburg = { latitude: 57.69226, longitude: 11.91737, label: 'Gateway' }
const home = gatewayRegion(gothenburg)
const lanes = (code: string, asn?: number) => classifySeries({ countryCode: code, asn }, home)
const hops = (code: string) => lanes(code).hops.map(hop => `${hop.from}>${hop.to}`)
const cableNames = (from: string, to: string) => cablesBetween(from, to).map(candidate => candidate.cable.name)
function series(id: string, countryCode: string, bytes = 100, asn?: number): MapSeries {
  return { id, trackId: id, label: id, client: 'c', site: id, hostname: id, chunks: [], startMs: 0, endMs: 1, lastActivityMs: 1, bytes, mapped: true, location: '', provider: '', countryCode, asn }
}
function location(id: string, position: MapPosition, items: MapSeries[]): LocationTraffic {
  return { id, label: id, detail: '', position, received: 0, sent: 0, partial: false, bytes: 0, lastActivityMs: 1, series: items }
}

describe('sea crossings on real cables', () => {
  it('places the gateway by its coordinates', () => {
    expect(home).toBe('nordic')
  })

  it('derives landing countries from the cable geometry', () => {
    const byName = new Map(CABLES.map(cable => [cable.name, cable]))
    expect(new Set(byName.get('Havfrue/AEC-2')!.landings.map(landing => landing.country))).toEqual(new Set(['DK', 'IE', 'NO', 'US']))
    expect(new Set(byName.get('C-Lion1')!.landings.map(landing => landing.country))).toEqual(new Set(['DE', 'FI']))
    for (const cable of CABLES) expect(cable.distances).toHaveLength(cable.landings.length)
  })

  it('requires a crossing where no overland route exists, over the cables that connect the regions', () => {
    expect(lanes('US').kind).toBe('required')
    expect(hops('US')).toEqual(['nordic>north_america'])
    expect(cableNames('nordic', 'north_america')).toContain('Havfrue/AEC-2')
    expect(lanes('IS').kind).toBe('required')
    expect(cableNames('nordic', 'iceland')).toContain('DANICE')
    expect(lanes('AU').kind).toBe('required')
    expect(lanes('BR').kind).toBe('required')
  })

  it('marks the sea as the usual, not the only, way where land connects', () => {
    expect(lanes('GB').kind).toBe('possible')
    expect(hops('FI')).toEqual(['nordic>finland'])
    expect(hops('IN')).toEqual(['europe>south_asia'])
    expect(lanes('SG').kind).toBe('possible')
  })

  it('draws nothing at sea for overland neighbours', () => {
    expect(lanes('SE').kind).toBe('none')
    expect(lanes('DE')).toMatchObject({ kind: 'none', hops: [] })
  })

  it('never places anycast or CDN networks across the sea, whatever their geolocation says', () => {
    expect(lanes('US', 13335)).toMatchObject({ kind: 'edge', hops: [] })
    expect(lanes('US', 15169).kind).toBe('edge')
    // A nearby edge location is consistent with local serving and stays overland.
    expect(lanes('DK', 15169).kind).toBe('none')
  })

  it('reports unknown or unmodelled countries as unknown', () => {
    expect(classifySeries({}, home).kind).toBe('unknown')
    expect(lanes('AQ').kind).toBe('unknown')
    expect(classifySeries({ countryCode: 'US' }, undefined).kind).toBe('unknown')
  })

  it('is symmetric in its crossings', () => {
    const there = regionCrossing('nordic', 'south_asia').hops.map(hop => hop.id)
    const back = regionCrossing('south_asia', 'nordic').hops.map(hop => hop.id)
    expect(back).toEqual([...there].reverse())
  })

  it('chooses landings near the actual gateway and destination', () => {
    const [nearSeattle] = cablesBetween('japan', 'north_america', [139.7, 35.7], [-122.3, 47.6])
    const [nearLosAngeles] = cablesBetween('japan', 'north_america', [139.7, 35.7], [-118.2, 34.1])
    expect(nearSeattle.to[1]).toBeGreaterThan(nearLosAngeles.to[1])
  })

  it('follows a cable between two landings, through branching units', () => {
    const cable: Cable = { id: 't', name: 'Test', color: '#000', lines: [[[0, 0], [5, 0], [10, 0]], [[5, 0], [5, 5]]], landings: [], distances: [] }
    expect(cableSection(cable, [0, 0], [5, 5])).toEqual([[[0, 0], [5, 0], [5, 5]]])
    // Disconnected lines: each side is drawn as far as it reaches, leaving the gap visible.
    const gap: Cable = { ...cable, id: 'gap', lines: [[[0, 0], [4, 0]], [[6, 0], [10, 0]]] }
    expect(cableSection(gap, [0, 0], [10, 0])).toEqual([[[0, 0], [4, 0]], [[10, 0], [6, 0]]])
    // Import-time joins (branch snaps, bridges between pieces) connect them.
    expect(cableSection({ ...gap, id: 'joined', joins: [[[4, 0], [6, 0]]] }, [0, 0], [10, 0])).toEqual([[[0, 0], [4, 0], [6, 0], [10, 0]]])
  })

  it('merges shared cable sections and connectors into one flow network', () => {
    const volumes = new Map([['a', { received: 80, sent: 20, partial: false }], ['b', { received: 40, sent: 10, partial: false }], ['cdn', { received: 500, sent: 5, partial: false }], ['de', { received: 7, sent: 3, partial: false }]])
    const network = buildSeaNetwork([
      location('ny', [-74, 40.7], [series('a', 'US'), series('cdn', 'US', 505, 13335)]),
      location('boston', [-71.1, 42.4], [series('b', 'US')]),
      location('berlin', [13.4, 52.5], [series('de', 'DE')]),
    ], gothenburg, volumes)
    const sea = network.edges.filter(edge => edge.kind === 'sea')
    expect(sea.length).toBeGreaterThan(0)
    expect(sea.every(edge => edge.hopId === 'nordic~north_america' && edge.confidence === 'required' && edge.candidates === cablesBetween('nordic', 'north_america').length)).toBe(true)
    expect(sea.some(edge => edge.received === 120 && edge.sent === 30 && edge.locationIds.join() === 'boston,ny')).toBe(true)
    expect(network.hops).toMatchObject([{ received: 120, sent: 30, confidence: 'required' }])
    expect(network.edges.find(edge => edge.id === 'land:gateway>loc:berlin')).toMatchObject({ kind: 'land', confidence: null })
    expect(network.totals).toMatchObject({ required: 150, edge: 505, none: 10 })
    expect(network.edgeNetworks).toEqual(['Cloudflare'])
    expect(network.edges.some(edge => edge.trackIds.includes('cdn'))).toBe(false)
  })

  it('lets a measured round trip overrule or confirm the inferred crossing', () => {
    const context = { origin: gothenburg, position: [-74, 40.7] as MapPosition }
    // "New York" answering in 4 ms was served nearby, whatever its ASN says.
    expect(classifySeries({ countryCode: 'US', rttMs: 4 }, home, context)).toMatchObject({ kind: 'nearby', hops: [] })
    // 95 ms is consistent with crossing the Atlantic; even an edge ASN does not veto it.
    const measured = classifySeries({ countryCode: 'US', asn: 15169, rttMs: 95 }, home, context)
    expect(measured).toMatchObject({ kind: 'required', measuredMs: 95 })
    expect(measured.hops.map(hop => hop.id)).toEqual(['nordic~north_america'])
    // Without a measurement, the CDN list still applies.
    expect(classifySeries({ countryCode: 'US', asn: 15169 }, home, context).kind).toBe('edge')
  })

  it('summarises bytes per class and crossing', () => {
    const summary = summarizeCrossings([location('us', [-74, 40.7], [series('a', 'US', 300), series('d', 'US', 25, 54113)]), location('gb', [-0.1, 51.5], [series('b', 'GB', 100)]), location('se', [18.07, 59.33], [series('c', 'SE', 50)])], gothenburg)
    expect(summary.totals).toMatchObject({ required: 300, possible: 100, none: 50, edge: 25 })
    expect(summary.total).toBe(475)
    expect(summary.hops.map(entry => [entry.hop.id, entry.bytes, entry.confidence])).toEqual([['nordic~north_america', 300, 'required'], ['british_isles~nordic', 100, 'possible']])
    expect(summary.edgeNetworks).toEqual(['Fastly'])
  })

  it('splits paths at the antimeridian', () => {
    const parts = splitAntimeridian([[170, 40], [190, 45], [200, 46]])
    expect(parts).toHaveLength(2)
    expect(parts[0][parts[0].length - 1]).toEqual([180, 42.5])
    expect(parts[1][0]).toEqual([-180, 42.5])
    expect(splitAntimeridian([[10, 0], [20, 0]])).toEqual([[[10, 0], [20, 0]]])
  })
})
