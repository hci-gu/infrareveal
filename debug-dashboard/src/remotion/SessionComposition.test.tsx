import { renderToStaticMarkup } from 'react-dom/server'
import { expect, it, vi } from 'vitest'
import type { GatewayData } from '@infrareveal/session-state'
import fixture from '../../../testdata/session-timeline-contract-v1.json'
import { SessionCompositionProjector } from '../model/sessionModel'
import { buildTrafficModel } from '../experiments/session-playback/trafficModel'
import { selectSceneWindow } from '../timeline/selectors/selectSceneWindow'
import { SessionComposition } from './SessionComposition'

const clock = vi.hoisted(() => ({ frame: 0 }))
vi.mock('remotion', () => ({ useCurrentFrame: () => clock.frame }))

it.each([0, 150, 299])('retains treemap markup at frame %i', async frame => {
  clock.frame = frame
  const data = { ...fixture.window, sessions: [fixture.session], selectedSession: fixture.session } as GatewayData
  const fromMs = Date.parse(fixture.session.started_at), toMs = Date.parse(fixture.session.ended_at)
  const { composition } = buildTrafficModel(data, new SessionCompositionProjector(), fromMs, toMs)
  const sceneWindow = selectSceneWindow(composition, { fromMs, toMs, overview: true, focusedServiceId: null, selectedClipId: null })
  const markup = renderToStaticMarkup(<SessionComposition sceneWindow={sceneWindow} />)
  expect(markup).toContain('Activity treemap')
  expect(markup).toContain('10.0.0.50 / example.com')
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(markup))
  expect(Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('')).toMatchSnapshot()
})
