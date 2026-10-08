import { describe, expect, it } from 'vitest'
import fixture from '../../../../testdata/route-evidence-contract-v1.json'
import { applyRouteEvidenceAt, routeForFlowAt, routeStateLabel, routeTopology } from './routeEvidence'
import { attachRouteEvidenceUpdates, normalizeRouteRecord } from './routeRecords'
import type { RouteEvidenceRecord } from './routeRecords'
import type { Route } from './types'

const route = fixture.route as Route
const legacy = fixture.legacyRoute as Route
const updates = fixture.updates as RouteEvidenceRecord[]

describe('shared route evidence contract', () => {
  it('attaches events by session, route ID and network epoch using parsed instants', () => {
    const [attached] = attachRouteEvidenceUpdates([route], updates)
    expect(attached.evidence_updates?.map(event => event.kind)).toEqual(fixture.expectedAttachedKinds)
    expect(attached.evidence_updates).toEqual(updates.slice(1, 4).map(({ kind, available_at, value }) => ({ kind, available_at, value })))
    expect(attachRouteEvidenceUpdates([attached], updates)).toEqual([attached])
  })

  it('projects confirmation and geography only at availability, retaining measurement age and alternatives', () => {
    const [attached] = attachRouteEvidenceUpdates([route], updates)
    const before = routeForFlowAt(route, [attached], Date.parse(fixture.cursors.beforeConfirmation))!
    expect(before.fresh_until).toBe(route.fresh_until)
    expect(before.hops?.[1].lat).toBeUndefined()
    const confirmed = routeForFlowAt(route, [attached], Date.parse(fixture.cursors.afterConfirmation))!
    expect(confirmed.valid_until).toBe('2026-09-10T12:00:15Z')
    expect(confirmed.hops?.[1].lat).toBeUndefined()
    const enriched = routeForFlowAt(route, [attached], Date.parse(fixture.cursors.afterEnrichment))!
    expect(enriched.hops?.[1]).toMatchObject({ address: '8.8.8.8', lat: 50.1, lon: 8.7, city: 'Frankfurt', accuracy_km: 100 })
    expect(enriched.measured_at).toBe(route.measured_at)
    expect(enriched.alternate_routes).toEqual(route.alternate_routes)
    expect(routeStateLabel(enriched, Date.parse(fixture.cursors.afterEnrichment))).toContain('cached 5s ago')
    expect(routeForFlowAt(route, [attached], Date.parse(fixture.cursors.afterInvalidation))).toBeNull()
    // Projection never mutates stored history when playback seeks backwards.
    expect(applyRouteEvidenceAt(attached, Date.parse(fixture.cursors.beforeConfirmation)).hops?.[1].lat).toBeUndefined()
  })

  it('preserves old flat geography, completed-time availability and alternate probes', () => {
    const normalized = normalizeRouteRecord(legacy)
    expect(normalized).toEqual(legacy)
    expect(normalized.available_at).toBe('')
    expect(routeForFlowAt(legacy, [normalized], Date.parse(legacy.completed_at) - 1)).toBeNull()
    expect(routeForFlowAt(legacy, [normalized], Date.parse(legacy.completed_at))?.hops).toEqual(legacy.hops)
  })

  it('fills a single structured responder without choosing a path through multiple replies', () => {
    const sparse = {
      ...route,
      hops: [
        { ttl: 1, replies: [{ address: '9.9.9.9', probe_id: 1, reported_rtt_ms: 2.5 }] },
        { ttl: 2, replies: [{ address: '8.8.8.8', probe_id: 2 }, { address: '8.8.4.4', probe_id: 3 }] },
      ],
    } as Route
    const normalized = normalizeRouteRecord(sparse)
    expect(normalized.hops?.[0]).toMatchObject({ address: '9.9.9.9', timings: [2.5], missing: false })
    expect(normalized.hops?.[1]).toMatchObject({ address: '', timings: [], missing: true })
    expect(routeTopology(normalized)[1]).toMatchObject({ state: 'ambiguous', addresses: ['8.8.8.8', '8.8.4.4'] })
  })
})
