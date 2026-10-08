import { afterEach, beforeEach, expect, it, vi } from 'vitest'
import type { GatewayData } from '@infrareveal/session-state'
import fixture from '../../../../testdata/session-timeline-contract-v1.json'
import { SessionCompositionProjector } from '../../model/sessionModel'
import { createRecordedRenderBundle } from '../../remotion/renderBundle'
import { selectSceneWindow } from '../../timeline/selectors/selectSceneWindow'
import { buildTrafficModel } from './trafficModel'

const epoch = Date.parse(fixture.session.started_at)
const scenarios = ['associated', 'independent', 'hidden', 'two clients', 'DNS only', 'missing timestamps', 'capture gap', 'mixed resolution', 'route revisions'] as const
type Scenario = typeof scenarios[number]

beforeEach(() => { vi.useFakeTimers(); vi.setSystemTime(epoch + 10_000) })
afterEach(() => vi.useRealTimers())

it.each(scenarios)('preserves the final Traffic model and v1 exports: %s', async scenario => {
  const data = inputFor(scenario)
  const model = buildTrafficModel(data, new SessionCompositionProjector(), epoch, epoch + 10_000)
  const exports = [false, true].map(overview => createRecordedRenderBundle(fixture.session.id,
    selectSceneWindow(model.composition, {
      fromMs: epoch + 5000, toMs: epoch + 8000, overview, focusedServiceId: null,
      selectedClipId: model.clips[0]?.id ?? null,
    }), fixture.session.ended_at))
  // Captured against 63c4521 before removing its discarded intermediate projection.
  expect(await digest({ model, exports })).toMatchSnapshot()
  expect(model.composition).toMatchObject({ width: 1440, height: 810, sessionStartMs: epoch, sessionEndMs: epoch + 10_000 })
  expect(exports.every(bundle => bundle.version === 1 && bundle.sceneWindow.clips.every(clip => !('samples' in clip.activity)))).toBe(true)
})

function inputFor(scenario: Scenario): GatewayData {
  const data = structuredClone({ ...fixture.window, sessions: [fixture.session], selectedSession: fixture.session }) as GatewayData
  const flow = data.flows[0], chunk = data.flowActivityChunks[0]
  if (scenario === 'independent' || scenario === 'hidden') {
    data.flowAssociations = []
    data.activityEpisodes = []
    if (scenario === 'independent') data.attributions = []
    else data.attributions[0].confidence = 'hidden'
  }
  if (scenario === 'two clients') {
    data.flows.push({ ...flow, id: 'other-client', client_ip: '10.0.0.51' })
    data.flowAssociations.push({ ...data.flowAssociations[0], id: 'wrong-client-association', flow: 'other-client' })
  }
  if (scenario === 'DNS only') data.flows = []
  if (scenario === 'missing timestamps') Object.assign(flow, { start: '', last_seen: '', created: '', updated: '' })
  if (scenario === 'capture gap') {
    Object.assign(chunk, { capture_complete: false, dropped_events: 2 })
    Object.assign(data.flowActivityWindows[0], { capture_complete: false, dropped_events: 3 })
  }
  if (scenario === 'mixed resolution') data.flowActivityChunks.push({
    ...chunk, id: 'coarse', bucket_ms: 5000,
    samples: { version: 1, bucket_ms: 5000, chunk_ms: 5000, samples: [[0, 100, 200, 1, 2]] },
  })
  if (scenario === 'route revisions') data.routes.push({
    ...data.routes[0], id: 'new-route', available_at: new Date(epoch + 6000).toISOString(),
    valid_until: new Date(epoch + 30_000).toISOString(), evidence_updates: [],
  })
  return data
}

async function digest(value: unknown) {
  const serialized = JSON.stringify(value, (_, entry) => {
    if (entry instanceof Map) return [...entry]
    return entry && typeof entry === 'object' && !Array.isArray(entry)
      ? Object.fromEntries(Object.entries(entry).sort(([a], [b]) => a.localeCompare(b)))
      : entry
  })
  const bytes = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(serialized))
  return Array.from(new Uint8Array(bytes), byte => byte.toString(16).padStart(2, '0')).join('')
}
