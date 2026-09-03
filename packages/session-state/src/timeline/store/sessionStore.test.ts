import { beforeEach, describe, expect, it } from 'vitest'
import type { Flow, FlowActivityChunk, GateEvent, Session, SessionWindow } from '../../data/types'
import {
  applyRealtimeBatch,
  applySessionWindow,
  clearDetailPages,
  configureDetailCacheBudget,
  observeTimelineLiveEdge,
  reconcileOverviewWindow,
  resetSessionTimeline,
  selectDetailGatewayData,
  sessionTimelineStore,
  setTimelineConnection,
  setTimelineManifest,
  setTimelineUI,
  tickTimelineClock,
} from './sessionStore'

const session: Session = {
  id: 'session-1',
  created: '2026-09-02T10:00:00Z',
  updated: '2026-09-02T10:00:00Z',
  name: 'Test',
  active: true,
  started_at: '2026-09-02T10:00:00Z',
}

describe('shared sessionTimelineStore', () => {
  beforeEach(() => resetSessionTimeline(session.id, [session]))

  it('anchors live time to the server manifest and keeps UI state separate', () => {
    setTimelineManifest({
      sessionId: session.id,
      name: session.name,
      startedAt: session.started_at!,
      endedAt: null,
      active: true,
      serverNow: '2026-09-02T10:02:00Z',
      watermark: 'rev-1',
      counts: { flows: 0 },
      coverage: { from: session.started_at!, to: '2026-09-02T10:02:00Z' },
    })
    setTimelineUI({ selectedClipId: 'clip:flow-1', viewMode: 'treemap' })

    const state = sessionTimelineStore.getState()
    expect(state.liveEdgeMs).toBe(Date.parse('2026-09-02T10:02:00Z'))
    expect(state.cursorMs).toBe(state.liveEdgeMs)
    expect(state.playback).toBe('following')
    expect(state.ui).toMatchObject({ selectedClipId: 'clip:flow-1', viewMode: 'treemap' })
  })

  it('applies revision-aware upserts and delete tombstones idempotently', () => {
    applySessionWindow(makeWindow('overview', [makeFlow('2026-09-02T10:00:02Z', 'open')]))
    applyRealtimeBatch([{
      collection: 'flows',
      action: 'update',
      record: makeFlow('2026-09-02T10:00:01Z', 'stale'),
    }])
    expect(sessionTimelineStore.getState().entities.flows.get('flow-1')?.state).toBe('open')

    applyRealtimeBatch([{
      collection: 'flows',
      action: 'update',
      record: makeFlow('2026-09-02T10:00:03Z', 'closed'),
    }])
    applyRealtimeBatch([{
      collection: 'flows',
      action: 'update',
      record: makeFlow('2026-09-02T10:00:03Z', 'closed'),
    }])
    expect(sessionTimelineStore.getState().entities.flows.size).toBe(1)
    expect(sessionTimelineStore.getState().entities.flows.get('flow-1')?.state).toBe('closed')

    applyRealtimeBatch([{
      collection: 'flows',
      action: 'delete',
      record: { id: 'flow-1', session: session.id, updated: '2026-09-02T10:00:04Z' },
    }])
    applyRealtimeBatch([{
      collection: 'flows',
      action: 'update',
      record: makeFlow('2026-09-02T10:00:03Z', 'stale-after-delete'),
    }])
    expect(sessionTimelineStore.getState().entities.flows.has('flow-1')).toBe(false)
    expect(sessionTimelineStore.getState().indexes.flows.query(
      Date.parse('2026-09-02T09:59:00Z'),
      Date.parse('2026-09-02T10:01:00Z'),
    ).size).toBe(0)
  })

  it('applies live flow updates from gateways whose records have no revision fields', () => {
    const first = makeFlow('2026-09-02T10:00:02Z', 'open')
    delete (first as Partial<Flow>).created
    delete (first as Partial<Flow>).updated
    applySessionWindow(makeWindow('overview', [first]))

    const liveUpdate = {
      ...first,
      last_seen: '2026-09-02T10:00:05Z',
      bytes_in: 50,
      state: 'established',
    }
    applyRealtimeBatch([{ collection: 'flows', action: 'update', record: liveUpdate }])

    expect(sessionTimelineStore.getState().entities.flows.get(first.id)).toMatchObject({
      last_seen: '2026-09-02T10:00:05Z',
      bytes_in: 50,
      state: 'established',
    })
  })

  it('retains detail records referenced by overlapping pages until the final owner is removed', () => {
    const shared = makeChunk('chunk-shared', '2026-09-02T10:00:05Z')
    applySessionWindow(makeWindow('50ms', [], [shared]), detailPage('page-1', 0))
    applySessionWindow(makeWindow('50ms', [], [shared]), detailPage('page-2', 5_000))

    const firstPageBytes = sessionTimelineStore.getState().pages.get('page-1')!.bytes
    configureDetailCacheBudget(firstPageBytes + 1)
    expect(sessionTimelineStore.getState().pages.size).toBe(1)
    expect(sessionTimelineStore.getState().entities.flowActivityChunks.has(shared.id)).toBe(true)

    clearDetailPages()
    expect(sessionTimelineStore.getState().entities.flowActivityChunks.has(shared.id)).toBe(false)
    expect(sessionTimelineStore.getState().detailRefCounts.flowActivityChunks.size).toBe(0)
  })

  it('freezes the projected live edge while realtime is unavailable', () => {
    setTimelineManifest({
      sessionId: session.id,
      name: session.name,
      startedAt: session.started_at!,
      endedAt: null,
      active: true,
      serverNow: '2026-09-02T10:02:00Z',
      watermark: 'rev-1',
      counts: { flows: 0 },
      coverage: { from: session.started_at!, to: '2026-09-02T10:02:00Z' },
    })
    const edge = sessionTimelineStore.getState().liveEdgeMs
    setTimelineConnection('polling', 'Realtime unavailable')
    tickTimelineClock()
    expect(sessionTimelineStore.getState().liveEdgeMs).toBe(edge)
  })

  it('accepts a trace edge but clamps future-dated events to server time', () => {
    const serverNow = Date.parse('2026-09-02T10:02:00Z')
    observeTimelineLiveEdge(serverNow + 30_000, serverNow)
    expect(sessionTimelineStore.getState().liveEdgeMs).toBe(serverNow)
    observeTimelineLiveEdge(serverNow - 5_000, serverNow + 1_000)
    expect(sessionTimelineStore.getState().liveEdgeMs).toBe(serverNow)
  })

  it('evicts least-recently-used detail pages and their unowned records', () => {
    const first = makeWindow('50ms', [], [makeChunk('chunk-1', '2026-09-02T10:00:00Z')])
    const second = makeWindow('50ms', [], [makeChunk('chunk-2', '2026-09-02T10:00:10Z')])
    applySessionWindow(first, detailPage('page-1', 0))
    applySessionWindow(second, detailPage('page-2', 10_000))
    configureDetailCacheBudget(sessionTimelineStore.getState().pages.get('page-2')!.bytes + 1)

    const state = sessionTimelineStore.getState()
    expect(state.cacheBytes).toBeLessThanOrEqual(state.detailCacheBudgetBytes)
    expect(state.pages.has('page-1')).toBe(false)
    expect(state.pages.has('page-2')).toBe(true)
    expect(state.entities.flowActivityChunks.has('chunk-1')).toBe(false)
    expect(selectDetailGatewayData(Date.parse('2026-09-02T10:00:10Z'), Date.parse('2026-09-02T10:00:20Z')).flowActivityChunks.map((item) => item.id)).toEqual(['chunk-2'])
  })

  it('keeps a 60-minute scrub bounded by the detail cache budget', () => {
    const budget = 24 * 1024
    configureDetailCacheBudget(budget)
    const startMs = Date.parse('2026-09-02T10:00:00Z')
    for (let segment = 0; segment < 360; segment += 1) {
      const offset = segment * 10_000
      applySessionWindow(
        makeWindow('50ms', [], [makeChunk(`chunk-${segment}`, new Date(startMs + offset).toISOString())]),
        detailPage(`page-${segment}`, offset),
      )
    }

    const state = sessionTimelineStore.getState()
    expect(state.cacheBytes).toBeLessThanOrEqual(budget)
    expect(state.pages.size).toBeLessThan(360)
    expect(state.entities.flowActivityChunks.size).toBe(state.pages.size)
  })

  it('repairs a missed delete from an authoritative reconciliation range', () => {
    const first = makeFlow('2026-09-02T10:00:02Z', 'open')
    const second = { ...makeFlow('2026-09-02T10:00:02Z', 'open'), id: 'flow-2' }
    applySessionWindow(makeWindow('overview', [first, second]))

    reconcileOverviewWindow(makeWindow('overview', [first]))

    expect(Array.from(sessionTimelineStore.getState().entities.flows.keys())).toEqual(['flow-1'])
  })

  it('indexes, updates, and evicts durable gate events with their detail page', () => {
    const queued = makeGateEvent('queued')
    const window = makeWindow('50ms')
    window.gateEvents = [queued]
    applySessionWindow(window, detailPage('gate-page', 0))
    expect(selectDetailGatewayData(Date.parse('2026-09-02T10:00:00Z'), Date.parse('2026-09-02T10:01:00Z')).gateEvents).toHaveLength(1)

    const approved: GateEvent = { ...queued, state: 'approved', decided_at: '2026-09-02T10:00:03Z', updated: '2026-09-02T10:00:04Z' }
    applyRealtimeBatch([{ collection: 'gateEvents', action: 'update', record: approved }])
    expect(sessionTimelineStore.getState().entities.gateEvents.get(queued.id)?.state).toBe('approved')
    clearDetailPages()
    expect(sessionTimelineStore.getState().entities.gateEvents.size).toBe(0)
    expect(sessionTimelineStore.getState().indexes.gates.query(Date.parse('2026-09-02T09:59:00Z'), Date.parse('2026-09-02T10:01:00Z')).size).toBe(0)
  })
})

function makeFlow(updated: string, state: string): Flow {
  return {
    id: 'flow-1',
    created: '2026-09-02T10:00:00Z',
    updated,
    session: session.id,
    client_ip: '192.168.0.2',
    destination_ip: '1.1.1.1',
    source_port: 50_000,
    destination_port: 443,
    protocol: 'tcp',
    state,
    start: '2026-09-02T10:00:00Z',
    last_seen: updated,
    bytes_out: 1,
    bytes_in: 2,
    packets_out: 1,
    packets_in: 1,
  }
}

function makeChunk(id: string, start: string): FlowActivityChunk {
  return {
    id,
    session: session.id,
    flow: 'flow-1',
    flow_key: 'flow-key',
    chunk_start: start,
    bucket_ms: 50,
    chunk_ms: 10_000,
    samples: { version: 1, padding: 'x'.repeat(600), samples: [] },
    wire_bytes_out: 0,
    wire_bytes_in: 0,
    payload_bytes_out: 0,
    payload_bytes_in: 0,
    packets_out: 0,
    packets_in: 0,
    tcp_flags_out: 0,
    tcp_flags_in: 0,
    capture_complete: true,
    dropped_events: 0,
    updated_at_source: start,
  }
}

function makeGateEvent(state: GateEvent['state']): GateEvent {
  return {
    id: 'gate-1', session: session.id, decision_id: 'decision-1', flow_key: 'flow-key',
    client_ip: '192.168.0.2', destination_ip: '1.1.1.1', source_port: 50_000,
    destination_port: 443, protocol: 'tcp', packet_count: 1, state, actor: '', reason: '',
    verdict_source: 'system', queued_at: '2026-09-02T10:00:02Z', wait_ms: 0,
    created: '2026-09-02T10:00:02Z', updated: '2026-09-02T10:00:02Z',
  }
}

function makeWindow(lod: SessionWindow['lod'], flows: Flow[] = [], chunks: FlowActivityChunk[] = []): SessionWindow {
  return {
    range: { from: '2026-09-02T10:00:00Z', to: '2026-09-02T10:01:00Z' },
    lod,
    watermark: 'rev',
    flows,
    dnsQueries: [],
    attributions: [],
    activityEpisodes: [],
    flowAssociations: [],
    flowActivityChunks: chunks,
    flowActivityWindows: [],
    flowActivityStatuses: [],
    destinations: [],
    routes: [],
    gateEvents: [],
    nextCursor: null,
  }
}

function detailPage(key: string, start: number) {
  return {
    key,
    fromMs: Date.parse('2026-09-02T10:00:00Z') + start,
    toMs: Date.parse('2026-09-02T10:00:00Z') + start + 10_000,
    lod: '50ms' as const,
    flowKey: 'flow-1',
    flowIds: new Set(['flow-1']),
  }
}
